//! Local, bounded authority for recurring private Slack notifications.
//! The skill may name an opaque grant, but only the native permission owner
//! reads and reserves the protected record.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use runx_contracts::sha256_prefixed;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::receipts::store::{LocalReceiptStore, ReceiptStoreError};

pub const NOTIFICATION_AUTHORITY_ID_ENV: &str = "RUNX_NOTIFICATION_AUTHORITY_ID";
pub const NOTIFICATION_SOURCE_SET_DIGEST_ENV: &str = "RUNX_NOTIFICATION_SOURCE_SET_DIGEST";
const SCHEMA: &str = "runx.notification_authorities.v1";
const MAX_LIFETIME_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationAuthorityGrant {
    pub authority_id: String,
    pub provider_grant_id: String,
    pub principal_ref: String,
    pub target: String,
    pub source_set_digest: String,
    pub created_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub max_posts_total: u32,
    pub max_posts_per_day: u32,
    pub max_text_bytes: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at_unix_seconds: Option<u64>,
    #[serde(default)]
    reservations: BTreeMap<String, NotificationReservation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NotificationAuthorityStatus {
    pub authority_id: String,
    pub provider_grant_id: String,
    pub principal_ref: String,
    pub target: String,
    pub source_set_digest: String,
    pub expires_at_unix_seconds: u64,
    pub revoked_at_unix_seconds: Option<u64>,
    pub max_posts_total: u32,
    pub max_posts_per_day: u32,
    pub used_posts_total: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotificationAuthorityGrantSpec {
    pub authority_id: String,
    pub provider_grant_id: String,
    pub principal_ref: String,
    pub target: String,
    pub source_set_digest: String,
    pub expires_at_unix_seconds: u64,
    pub max_posts_total: u32,
    pub max_posts_per_day: u32,
    pub max_text_bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NotificationAuthorityState {
    schema: String,
    grants: BTreeMap<String, NotificationAuthorityGrant>,
}

impl Default for NotificationAuthorityState {
    fn default() -> Self {
        Self {
            schema: SCHEMA.to_owned(),
            grants: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NotificationReservation {
    plan_digest: String,
    run_id: String,
    day: u64,
    phase: ReservationPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReservationPhase {
    Reserved,
    Dispatched,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct NotificationIntent<'a> {
    pub authority_id: &'a str,
    pub provider_grant_id: &'a str,
    pub principal_ref: &'a str,
    pub target: &'a str,
    pub source_set_digest: &'a str,
    pub plan_digest: &'a str,
    pub idempotency_key: &'a str,
    pub run_id: &'a str,
    pub text: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct NotificationRequest {
    pub authority_id: String,
    pub source_set_digest: String,
    pub run_id: String,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct NotificationReservationProof {
    pub authority_id: String,
    pub reservation_key: String,
    pub approval_key: String,
}

#[derive(Debug, Error)]
pub enum NotificationAuthorityError {
    #[error("notification authority is invalid: {0}")]
    Invalid(&'static str),
    #[error("notification authority denied: {0}")]
    Denied(&'static str),
    #[error("notification outcome requires reconciliation: {0}")]
    Unknown(&'static str),
    #[error("notification authority state is unavailable: {0}")]
    Store(#[from] ReceiptStoreError),
}

impl NotificationAuthorityGrant {
    pub fn new(spec: NotificationAuthorityGrantSpec) -> Result<Self, NotificationAuthorityError> {
        let now = now_unix_seconds();
        let grant = Self {
            authority_id: spec.authority_id,
            provider_grant_id: spec.provider_grant_id,
            principal_ref: spec.principal_ref,
            target: spec.target,
            source_set_digest: spec.source_set_digest,
            created_at_unix_seconds: now,
            expires_at_unix_seconds: spec.expires_at_unix_seconds,
            max_posts_total: spec.max_posts_total,
            max_posts_per_day: spec.max_posts_per_day,
            max_text_bytes: spec.max_text_bytes,
            revoked_at_unix_seconds: None,
            reservations: BTreeMap::new(),
        };
        validate_grant(&grant, now)?;
        Ok(grant)
    }
}

pub fn install_notification_authority(
    store_root: &Path,
    grant: NotificationAuthorityGrant,
) -> Result<(), NotificationAuthorityError> {
    validate_grant(&grant, now_unix_seconds())?;
    LocalReceiptStore::new(store_root)
        .update_notification_authority_state::<NotificationAuthorityState, _>(|state| {
            validate_state(state)?;
            let result = match state.grants.get(&grant.authority_id) {
                Some(existing) if existing == &grant => Ok(()),
                Some(_) => Err(NotificationAuthorityError::Denied(
                    "authority id already has different content",
                )),
                None => {
                    state.grants.insert(grant.authority_id.clone(), grant);
                    Ok(())
                }
            };
            Ok(result)
        })?
}

pub fn revoke_notification_authority(
    store_root: &Path,
    authority_id: &str,
) -> Result<(), NotificationAuthorityError> {
    let now = now_unix_seconds();
    LocalReceiptStore::new(store_root)
        .update_notification_authority_state::<NotificationAuthorityState, _>(|state| {
            validate_state(state)?;
            let result = match state.grants.get_mut(authority_id) {
                Some(grant) => {
                    grant.revoked_at_unix_seconds.get_or_insert(now);
                    Ok(())
                }
                None => Err(NotificationAuthorityError::Denied(
                    "authority id is unknown",
                )),
            };
            Ok(result)
        })?
}

pub fn notification_authority_status(
    store_root: &Path,
    authority_id: &str,
) -> Result<Option<NotificationAuthorityStatus>, NotificationAuthorityError> {
    let Some(state) = LocalReceiptStore::new(store_root)
        .read_notification_authority_state::<NotificationAuthorityState>()?
    else {
        return Ok(None);
    };
    validate_state(&state)?;
    Ok(state
        .grants
        .get(authority_id)
        .map(|grant| NotificationAuthorityStatus {
            authority_id: grant.authority_id.clone(),
            provider_grant_id: grant.provider_grant_id.clone(),
            principal_ref: grant.principal_ref.clone(),
            target: grant.target.clone(),
            source_set_digest: grant.source_set_digest.clone(),
            expires_at_unix_seconds: grant.expires_at_unix_seconds,
            revoked_at_unix_seconds: grant.revoked_at_unix_seconds,
            max_posts_total: grant.max_posts_total,
            max_posts_per_day: grant.max_posts_per_day,
            used_posts_total: grant.reservations.len(),
        }))
}

/// A missing reservation proves that this exact notification never reached the
/// native dispatch boundary. An unknown authority is not proof of absence.
pub fn notification_intent_has_reservation(
    store_root: &Path,
    authority_id: &str,
    idempotency_key: &str,
) -> Result<bool, NotificationAuthorityError> {
    if idempotency_key.is_empty() {
        return Err(NotificationAuthorityError::Invalid(
            "notification identity is incomplete",
        ));
    }
    let state = LocalReceiptStore::new(store_root)
        .read_notification_authority_state::<NotificationAuthorityState>()?
        .ok_or(NotificationAuthorityError::Denied(
            "authority id is unknown",
        ))?;
    validate_state(&state)?;
    let grant = state
        .grants
        .get(authority_id)
        .ok_or(NotificationAuthorityError::Denied(
            "authority id is unknown",
        ))?;
    Ok(grant
        .reservations
        .contains_key(&sha256_prefixed(idempotency_key.as_bytes())))
}

pub(super) fn reserve_notification(
    store_root: &Path,
    intent: &NotificationIntent<'_>,
    confirmed_recovery: bool,
) -> Result<NotificationReservationProof, NotificationAuthorityError> {
    reserve_notification_at(store_root, intent, now_unix_seconds(), confirmed_recovery)
}

fn reserve_notification_at(
    store_root: &Path,
    intent: &NotificationIntent<'_>,
    now: u64,
    confirmed_recovery: bool,
) -> Result<NotificationReservationProof, NotificationAuthorityError> {
    let reservation_key = sha256_prefixed(intent.idempotency_key.as_bytes());
    LocalReceiptStore::new(store_root)
        .update_notification_authority_state::<NotificationAuthorityState, _>(|state| {
            validate_state(state)?;
            let result = match state.grants.get_mut(intent.authority_id) {
                Some(grant) => {
                    reserve_in_grant(grant, intent, &reservation_key, now, confirmed_recovery)
                }
                None => Err(NotificationAuthorityError::Denied(
                    "authority id is unknown",
                )),
            };
            Ok(result)
        })?
}

fn reserve_in_grant(
    grant: &mut NotificationAuthorityGrant,
    intent: &NotificationIntent<'_>,
    reservation_key: &str,
    now: u64,
    confirmed_recovery: bool,
) -> Result<NotificationReservationProof, NotificationAuthorityError> {
    validate_intent(grant, intent)?;
    match grant.reservations.get(reservation_key) {
        Some(existing)
            if existing.plan_digest == intent.plan_digest && existing.run_id == intent.run_id =>
        {
            if confirmed_recovery && existing.phase == ReservationPhase::Dispatched {
                return Ok(reservation_proof(grant, reservation_key));
            }
        }
        Some(_) => {
            return Err(NotificationAuthorityError::Denied(
                "idempotency key belongs to another notification",
            ));
        }
        None => {
            if confirmed_recovery {
                return Err(NotificationAuthorityError::Denied(
                    "confirmed recovery has no prior reservation",
                ));
            }
        }
    }
    if grant.revoked_at_unix_seconds.is_some() {
        return Err(NotificationAuthorityError::Denied("authority is revoked"));
    }
    if now >= grant.expires_at_unix_seconds {
        return Err(NotificationAuthorityError::Denied("authority is expired"));
    }
    if !grant.reservations.contains_key(reservation_key) {
        if grant.reservations.len() >= grant.max_posts_total as usize {
            return Err(NotificationAuthorityError::Denied(
                "total post quota exhausted",
            ));
        }
        let day = now / 86_400;
        if grant
            .reservations
            .values()
            .filter(|reservation| reservation.day == day)
            .count()
            >= grant.max_posts_per_day as usize
        {
            return Err(NotificationAuthorityError::Denied(
                "daily post quota exhausted",
            ));
        }
        grant.reservations.insert(
            reservation_key.to_owned(),
            NotificationReservation {
                plan_digest: intent.plan_digest.to_owned(),
                run_id: intent.run_id.to_owned(),
                day,
                phase: ReservationPhase::Reserved,
            },
        );
    }
    Ok(reservation_proof(grant, reservation_key))
}

fn reservation_proof(
    grant: &NotificationAuthorityGrant,
    reservation_key: &str,
) -> NotificationReservationProof {
    NotificationReservationProof {
        authority_id: grant.authority_id.clone(),
        reservation_key: reservation_key.to_owned(),
        approval_key: sha256_prefixed(
            format!("{}\0{}", grant.authority_id, reservation_key).as_bytes(),
        ),
    }
}

pub(super) fn mark_notification_dispatch(
    store_root: &Path,
    proof: &NotificationReservationProof,
    plan_digest: &str,
) -> Result<(), NotificationAuthorityError> {
    mark_notification_dispatch_at(store_root, proof, plan_digest, now_unix_seconds())
}

pub(super) fn reset_notification_after_rejection(
    store_root: &Path,
    proof: &NotificationReservationProof,
    plan_digest: &str,
) -> Result<(), NotificationAuthorityError> {
    LocalReceiptStore::new(store_root)
        .update_notification_authority_state::<NotificationAuthorityState, _>(|state| {
            validate_state(state)?;
            let result = state
                .grants
                .get_mut(&proof.authority_id)
                .and_then(|grant| grant.reservations.get_mut(&proof.reservation_key))
                .filter(|reservation| reservation.plan_digest == plan_digest)
                .map_or_else(
                    || {
                        Err(NotificationAuthorityError::Denied(
                            "reservation does not match rejected notification",
                        ))
                    },
                    |reservation| {
                        reservation.phase = ReservationPhase::Reserved;
                        Ok(())
                    },
                );
            Ok(result)
        })?
}

fn mark_notification_dispatch_at(
    store_root: &Path,
    proof: &NotificationReservationProof,
    plan_digest: &str,
    now: u64,
) -> Result<(), NotificationAuthorityError> {
    LocalReceiptStore::new(store_root)
        .update_notification_authority_state::<NotificationAuthorityState, _>(|state| {
            validate_state(state)?;
            let result = match state.grants.get_mut(&proof.authority_id) {
                Some(grant)
                    if grant.revoked_at_unix_seconds.is_none()
                        && now < grant.expires_at_unix_seconds =>
                {
                    match grant.reservations.get(&proof.reservation_key) {
                        Some(reservation)
                            if reservation.plan_digest == plan_digest
                                && reservation.phase == ReservationPhase::Reserved =>
                        {
                            let dispatch_day = now / 86_400;
                            if reservation.day != dispatch_day
                                && grant
                                    .reservations
                                    .values()
                                    .filter(|other| other.day == dispatch_day)
                                    .count()
                                    >= grant.max_posts_per_day as usize
                            {
                                Err(NotificationAuthorityError::Denied(
                                    "daily post quota exhausted at dispatch",
                                ))
                            } else if let Some(reservation) =
                                grant.reservations.get_mut(&proof.reservation_key)
                            {
                                reservation.day = dispatch_day;
                                reservation.phase = ReservationPhase::Dispatched;
                                Ok(())
                            } else {
                                Err(NotificationAuthorityError::Denied(
                                    "reservation disappeared before dispatch",
                                ))
                            }
                        }
                        Some(_) => Err(NotificationAuthorityError::Unknown(
                            "notification was already dispatched or changed",
                        )),
                        None => Err(NotificationAuthorityError::Denied("reservation is missing")),
                    }
                }
                Some(_) => Err(NotificationAuthorityError::Denied(
                    "authority is no longer active",
                )),
                None => Err(NotificationAuthorityError::Denied(
                    "authority id is unknown",
                )),
            };
            Ok(result)
        })?
}

fn validate_intent(
    grant: &NotificationAuthorityGrant,
    intent: &NotificationIntent<'_>,
) -> Result<(), NotificationAuthorityError> {
    if grant.provider_grant_id != intent.provider_grant_id
        || grant.principal_ref != intent.principal_ref
        || grant.target != intent.target
        || grant.source_set_digest != intent.source_set_digest
    {
        return Err(NotificationAuthorityError::Denied(
            "grant, principal, destination or source set differs",
        ));
    }
    if intent.text.is_empty()
        || intent.text.len() > grant.max_text_bytes as usize
        || intent.text.contains("<!")
        || intent.text.contains("<@")
        || intent.text.contains("@channel")
        || intent.text.contains("@here")
        || intent.text.contains("@everyone")
    {
        return Err(NotificationAuthorityError::Denied(
            "notification text violates the grant",
        ));
    }
    if intent.plan_digest.is_empty()
        || intent.idempotency_key.is_empty()
        || intent.run_id.is_empty()
    {
        return Err(NotificationAuthorityError::Denied(
            "notification identity is incomplete",
        ));
    }
    Ok(())
}

fn validate_grant(
    grant: &NotificationAuthorityGrant,
    now: u64,
) -> Result<(), NotificationAuthorityError> {
    if grant.authority_id.is_empty()
        || grant.authority_id.len() > 128
        || !grant
            .authority_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(NotificationAuthorityError::Invalid(
            "authority id must be a safe identifier",
        ));
    }
    if grant.provider_grant_id.is_empty()
        || grant.provider_grant_id.len() > 512
        || grant.provider_grant_id.chars().any(char::is_control)
        || grant.principal_ref.is_empty()
        || grant.principal_ref.len() > 512
        || grant.principal_ref.chars().any(char::is_control)
    {
        return Err(NotificationAuthorityError::Invalid(
            "grant and principal are required",
        ));
    }
    let Some((workspace, channel)) = grant
        .target
        .strip_prefix("slack://")
        .and_then(|rest| rest.split_once('/'))
    else {
        return Err(NotificationAuthorityError::Invalid(
            "target must be an exact Slack channel locator",
        ));
    };
    if workspace.is_empty()
        || channel.is_empty()
        || !workspace
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        || !channel
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(NotificationAuthorityError::Invalid(
            "target must be an exact Slack channel locator",
        ));
    }
    if !valid_digest(&grant.source_set_digest) {
        return Err(NotificationAuthorityError::Invalid(
            "source set digest must be SHA-256",
        ));
    }
    if grant.expires_at_unix_seconds <= now
        || grant.expires_at_unix_seconds > now.saturating_add(MAX_LIFETIME_SECONDS)
        || grant.created_at_unix_seconds > now
        || now.saturating_sub(grant.created_at_unix_seconds) > 60
    {
        return Err(NotificationAuthorityError::Invalid(
            "expiry must be within 30 days",
        ));
    }
    if grant.max_posts_total == 0
        || grant.max_posts_total > 1000
        || grant.max_posts_per_day == 0
        || grant.max_posts_per_day > 100
        || grant.max_text_bytes == 0
        || grant.max_text_bytes > 4000
    {
        return Err(NotificationAuthorityError::Invalid(
            "quotas exceed the notification ceiling",
        ));
    }
    if grant.revoked_at_unix_seconds.is_some() || !grant.reservations.is_empty() {
        return Err(NotificationAuthorityError::Invalid(
            "a new grant cannot carry prior state",
        ));
    }
    Ok(())
}

fn validate_state(state: &NotificationAuthorityState) -> Result<(), ReceiptStoreError> {
    if state.schema != SCHEMA
        || state
            .grants
            .iter()
            .any(|(id, grant)| id != &grant.authority_id)
    {
        return Err(ReceiptStoreError::MalformedEffectState {
            path: Path::new("notification-authorities.json").to_path_buf(),
            message: "notification authority state has an invalid schema or key".to_owned(),
        });
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const SOURCE_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PLAN_DIGEST: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn grant(now: u64, daily: u32, total: u32) -> NotificationAuthorityGrant {
        NotificationAuthorityGrant::new(NotificationAuthorityGrantSpec {
            authority_id: "assistant-notify".to_owned(),
            provider_grant_id: "provider-grant".to_owned(),
            principal_ref: "runx:principal:operator:test".to_owned(),
            target: "slack://T123/C456".to_owned(),
            source_set_digest: SOURCE_DIGEST.to_owned(),
            expires_at_unix_seconds: now + 86_400,
            max_posts_total: total,
            max_posts_per_day: daily,
            max_text_bytes: 400,
        })
        .expect("grant fixture")
    }

    fn intent<'a>(key: &'a str, run_id: &'a str) -> NotificationIntent<'a> {
        NotificationIntent {
            authority_id: "assistant-notify",
            provider_grant_id: "provider-grant",
            principal_ref: "runx:principal:operator:test",
            target: "slack://T123/C456",
            source_set_digest: SOURCE_DIGEST,
            plan_digest: PLAN_DIGEST,
            idempotency_key: key,
            run_id,
            text: "One useful private update.",
        }
    }

    #[test]
    fn exact_reservation_read_distinguishes_denial_from_possible_dispatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let now = now_unix_seconds();
        install_notification_authority(temp.path(), grant(now, 2, 2))?;
        assert!(!notification_intent_has_reservation(
            temp.path(),
            "assistant-notify",
            "message-1"
        )?);
        reserve_notification_at(temp.path(), &intent("message-1", "run-1"), now, false)?;
        assert!(notification_intent_has_reservation(
            temp.path(),
            "assistant-notify",
            "message-1"
        )?);
        assert!(!notification_intent_has_reservation(
            temp.path(),
            "assistant-notify",
            "message-2"
        )?);
        assert!(notification_intent_has_reservation(temp.path(), "missing", "message-2").is_err());
        Ok(())
    }

    #[test]
    fn authority_binds_identity_payload_and_quota() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let now = now_unix_seconds();
        install_notification_authority(temp.path(), grant(now, 1, 2))?;
        let first =
            reserve_notification_at(temp.path(), &intent("message-1", "run-1"), now, false)?;
        assert_eq!(
            reserve_notification_at(temp.path(), &intent("message-1", "run-1"), now, false)?,
            first
        );
        let mut wrong = intent("message-2", "run-2");
        wrong.target = "slack://T123/C999";
        assert!(reserve_notification_at(temp.path(), &wrong, now, false).is_err());
        wrong.target = "slack://T123/C456";
        wrong.principal_ref = "runx:principal:operator:other";
        assert!(reserve_notification_at(temp.path(), &wrong, now, false).is_err());
        wrong.principal_ref = "runx:principal:operator:test";
        wrong.source_set_digest =
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        assert!(reserve_notification_at(temp.path(), &wrong, now, false).is_err());
        assert!(
            reserve_notification_at(temp.path(), &intent("message-2", "run-2"), now, false)
                .is_err()
        );
        assert!(
            reserve_notification_at(
                temp.path(),
                &intent("message-2", "run-2"),
                now + 86_400,
                false
            )
            .is_err()
        );
        let status = notification_authority_status(temp.path(), "assistant-notify")?
            .ok_or("missing authority")?;
        assert_eq!(status.used_posts_total, 1);
        mark_notification_dispatch_at(temp.path(), &first, PLAN_DIGEST, now)?;
        assert!(matches!(
            mark_notification_dispatch_at(temp.path(), &first, PLAN_DIGEST, now),
            Err(NotificationAuthorityError::Unknown(_))
        ));
        revoke_notification_authority(temp.path(), "assistant-notify")?;
        assert!(
            reserve_notification_at(temp.path(), &intent("message-3", "run-3"), now, false)
                .is_err()
        );
        assert_eq!(
            reserve_notification_at(
                temp.path(),
                &intent("message-1", "run-1"),
                now + 86_400,
                true
            )?,
            first
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(temp.path().join("notification-authorities.json"))?
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        Ok(())
    }

    #[test]
    fn concurrent_reservations_cannot_exceed_one_post() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let now = now_unix_seconds();
        install_notification_authority(temp.path(), grant(now, 1, 1))?;
        let root = temp.path().to_path_buf();
        let handles = ["a", "b"].map(|key| {
            let root = root.clone();
            std::thread::spawn(move || {
                reserve_notification_at(&root, &intent(key, key), now, false).is_ok()
            })
        });
        let admitted = handles
            .into_iter()
            .map(std::thread::JoinHandle::join)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "reservation thread failed")?
            .into_iter()
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(admitted, 1);
        Ok(())
    }

    #[test]
    fn revocation_between_reservation_and_dispatch_stops_the_post()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let now = now_unix_seconds();
        install_notification_authority(temp.path(), grant(now, 1, 1))?;
        let proof =
            reserve_notification_at(temp.path(), &intent("message-1", "run-1"), now, false)?;
        revoke_notification_authority(temp.path(), "assistant-notify")?;
        assert!(matches!(
            mark_notification_dispatch_at(temp.path(), &proof, PLAN_DIGEST, now),
            Err(NotificationAuthorityError::Denied(_))
        ));
        Ok(())
    }

    #[test]
    fn old_reservations_cannot_cross_midnight_to_exceed_the_daily_dispatch_quota()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let now = now_unix_seconds();
        let midnight = (now / 86_400 + 1) * 86_400;
        install_notification_authority(temp.path(), grant(now, 1, 2))?;
        let old = reserve_notification_at(
            temp.path(),
            &intent("message-1", "run-1"),
            midnight - 1,
            false,
        )?;
        let fresh = reserve_notification_at(
            temp.path(),
            &intent("message-2", "run-2"),
            midnight + 1,
            false,
        )?;
        assert!(matches!(
            mark_notification_dispatch_at(temp.path(), &old, PLAN_DIGEST, midnight + 2),
            Err(NotificationAuthorityError::Denied(_))
        ));
        mark_notification_dispatch_at(temp.path(), &fresh, PLAN_DIGEST, midnight + 2)?;
        Ok(())
    }
}
