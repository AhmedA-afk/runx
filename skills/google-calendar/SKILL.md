---
name: google-calendar
description: Read a selected Google Calendar's bounded events or free/busy window through a governed connection, preserving coverage and time semantics for downstream planning.
---
# Google Calendar

Use this skill when a decision needs current events or busy intervals from a calendar the operator has explicitly selected. The default `events` runner reads expanded event instances over a window of at most 30 days. `freebusy` reads one selected calendar's busy intervals. Both use the native `provider.read` boundary, an exact calendar target and the least-privilege Google OAuth scope; neither can write, RSVP or invite anyone.

Connect the intended Google account to `google-calendar` with `events.read` and/or `freebusy.read`. An Analytics or Search Console connection does not grant Calendar access. Supply the exact calendar ID and offset-bearing start/end instants. `primary` means the connected account's primary calendar. For multiple calendars, call the runner separately for each selected ID and keep each result's coverage. A read failure, a provider error or an incomplete event page means unknown coverage, not a free slot.

The returned `calendar_context` preserves source status, selected target, window, observation time, expanded recurring-instance identity, all-day dates and their exclusive end, cancellation, transparency, self-response and busy intervals. Private event titles are removed. A `partial` or `blocked` decision cannot establish availability. Event absence is meaningful only with complete coverage. Refresh evidence before proposing a meeting time; the assistant may use it for preparation and attention timing. `chief-of-staff` owns any scheduling or reply proposal using this packet plus bounded mail context. It must derive available slots from complete fresh evidence and working-hour policy; this skill does not offer slots or send messages.

`normalize-supplied` accepts already collected readback for composition without another provider call. Its output says `supplied_result` and `not_called`; only the prior receipt can attest where those bytes came from. Keep that receipt reference with downstream work. Do not use an unverified supplied packet as proof of a live Google read. A new live read uses `events` or `freebusy`. No sync-token store, mirrored event database, webhook loop or calendar mutation lives here.

Example: run `events` for `primary`, `2026-10-04T00:00:00+11:00` through `2026-10-11T00:00:00+11:00`; feed the resulting context and its receipt to the assistant. If the result is partial, retry the same bounded window before declaring the calendar clear. If the goal is to create or move an event, use a separately governed future mutation capability; this read-only skill must stop.
