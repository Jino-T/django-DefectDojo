---
title: "Bulk Editing Findings"
description: "Apply metadata changes, tags, notes, and review to many Findings at once in the DefectDojo Pro UI"
audience: pro
weight: 3
---

In the DefectDojo Pro UI, Findings can be edited in bulk from any Finding List — the **All Findings** page, or the Findings list within a Test.

## Selecting Findings for Bulk Edit

In any Findings table, use the checkboxes next to Findings to select them. Selecting one or more Findings reveals a **bulk-action bar** with the following controls:

* **Bulk Edit** — opens a single form where you apply metadata changes, tags, notes, and review requests to every selected Finding. This is the main consolidated surface (detailed below).
* **Risk Acceptance** — add the selected Findings to a new or existing **Full Risk Acceptance**.
* **Finding Group** — add the selected Findings to a new or existing **Finding Group**, or remove them from their group.
* **Merge** — merge the selected Findings into a single Finding.
* **Delete** — delete the selected Findings (with confirmation).

A control is disabled when the action can't apply to your current selection — see [Availability and skipped Findings](#availability-and-skipped-findings).

## Bulk Edit

The **Bulk Edit** button opens one form containing all of the field-level bulk actions. Set only the fields you want to change and leave the rest untouched, then click **Update Selected Findings** to apply. The available actions are:

* **Severity** — set the severity (Critical, High, Medium, Low, or Info).
* **Status** — apply one of Active, Verified, False Positive, Out of Scope, Mitigated, or Under Defect Review.
* **Date** — set the discovery date.
* **Planned Remediation Date** and **Planned Remediation Version**.
* **Simple Risk Acceptance** — Accept Risk or Unaccept Risk. Applied only to Findings whose Asset has Simple Risk Acceptance enabled; others are skipped.
* **Tags** — add tags to the selected Findings, or use the **Append / Replace** toggle to overwrite each Finding's entire tag set (**Append** adds the tags; **Replace** replaces all existing tags).
* **Replace Specific Tag** — swap one named tag for another (see below).
* **Note** — add a note, with an optional note type, to every selected Finding.
* **Review** — request or clear review on the selected Findings (see below).
* **Push to Jira** — queue the selected Findings to push to Jira. Shown only when the Jira integration is enabled.
* **Push to Connector** — dispatch the selected Findings to your configured connector. Shown only when that feature is enabled.
* **Move** — reassign the selected Findings to a Test in a different Asset (see below).

### Replace Specific Tag

**Replace Specific Tag** performs a targeted, non-destructive tag swap. Enter the tag to replace in **Existing Tag to Replace** and the replacement in **New Tag**. For each selected Finding that actually carries the old tag, DefectDojo removes that one tag and adds the new one — every other tag is preserved, and Findings that don't have the old tag are left unchanged.

This is different from the **Tags** field above: **Tags** either *adds* tags (Append) or *overwrites the whole tag set* (Replace), whereas **Replace Specific Tag** changes only the one named tag.

### Review

The **Review** action manages peer review across all selected Findings:

* **Request Review** — choose one or more **Reviewers** and enter a **Review Note** (required). Each selected Finding is set to *Under Review* (Active, not Verified), the chosen reviewers are assigned, a review-request note is added, and the reviewers are notified.
* **Clear Review** — enter a **Review Note** (required) to take the selected Findings out of the *Under Review* state and clear their assigned reviewers.

The reviewers you can choose from are the users with edit access to the selected Findings.

### Move

The **Move** section reassigns the selected Findings to a Test in a different Asset — useful when a single scan report covers several domains and its Findings all landed in one Asset.

Choose the destination with the **Move to Asset**, **Engagement**, and **Test** dropdowns. Each narrows the next, so the Engagement list only offers Engagements in the Asset you picked, and the Test list only Tests in that Engagement. There are two ways to finish:

* **Pick an existing Test.** The Findings are attached to that Test.
* **Pick only an Asset** and tick **Create a matching engagement and test if none exists.** DefectDojo mirrors each Finding's current Engagement and Test into the destination Asset, matching an Engagement by **name** and a Test by **scan type and title**. An existing match is reused; only what is missing is created, and a created Engagement inherits the source Engagement's dates and lead.

A selection can span several source Assets — each Finding is mirrored from its own Engagement and Test.

Moving a Finding also updates the things that belong to its old position in the hierarchy:

* Its **Endpoints** (or **Locations**) are re-homed onto the destination Asset, so they no longer point at the Asset it came from. An Endpoint shared with a Finding that stayed behind is left in place for that Finding.
* It is removed from its **Finding Group**, because a group belongs to a single Test.
* It is removed from any **Risk Acceptance** on the source Engagement, because a Risk Acceptance belongs to a single Engagement. Re-accept the risk in the destination Engagement if it still applies.
* Its **SLA** dates are recalculated against the destination Asset's SLA configuration, which may change its due date.
* **Deduplication** runs again in the destination's scope.
* A **note** is added to each moved Finding recording where it came from and where it went.

Moving requires edit permission on every selected Finding and on the destination Asset.

## Risk Acceptance, Finding Group, Merge, and Delete

The remaining bulk-action buttons open their own dialogs:

* **Risk Acceptance** — create a new **Full Risk Acceptance** to govern the selected Findings, or add them to an existing one.
* **Finding Group** — create a new **Finding Group**, add the Findings to an existing group, or remove them from their current group. Finding Groups can only be created within a single **Test** — Findings from different Tests, Engagements, or Assets cannot share a group.
* **Merge** — merge multiple selected Findings (all from the same Asset) into one.
* **Delete** — delete the selected Findings after confirming in a popup.

## Availability and skipped Findings

Each bulk action is available only when it can apply to your whole selection:

* **Bulk Edit**, tags, and review require every selected Finding to be editable by you.
* **Risk Acceptance** is unavailable if any selected Finding is not editable, is already risk-accepted, or is a duplicate.
* **Finding Group** creation requires every Finding to be editable, ungrouped, and in the same Test.
* **Merge** requires more than one Finding, all editable and from the same Asset.
* **Delete** requires every selected Finding to be deletable by you.

When an action runs but some Findings can't be updated — for example they aren't editable by you, are already under review, or belong to an Asset without Simple Risk Acceptance enabled — DefectDojo applies the change to the rest and shows a **"One or More Findings Skipped"** warning explaining why each was skipped.
