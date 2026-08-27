"""
Service-level tests for re-homing the endpoints (legacy) or locations (V3) of a
*set of findings* onto a new product.

An endpoint/location carries its own product association, independent of the
``finding -> test -> engagement -> product`` chain, so moving findings between
products leaves those associations pointing at the source product unless they are
re-homed. ``dojo.engagement.services.reassign_engagement_product_endpoints`` has
done this for a whole engagement since #15575; ``reassign_finding_product_endpoints``
generalizes the same logic to an arbitrary finding queryset so a *finding* move can
reuse it (see sc-14815), with the engagement entry point delegating to it.

The correctness-critical case here is the shared-location one: dropping the source
product's association is only safe when no finding remaining in that product still
references the location.

Both regimes are driven by patching ``locations_enabled`` -- the resolver the service
actually calls -- rather than by the ``skip_unless_v2``/``skip_unless_v3`` decorators,
which read ``settings.V3_FEATURE_LOCATIONS`` at import time. That matters twice over:
the skip approach leaves whichever branch the environment disables permanently
unexercised, and flipping the setting re-wires the URLconf (pulling in API v3, whose
dependencies are absent from some images). Patching the resolver covers both branches
in a single run, in any environment.
"""
from unittest.mock import patch

from django.utils import timezone

from dojo.engagement.services import reassign_engagement_product_endpoints
from dojo.finding.services import reassign_finding_product_endpoints
from dojo.location.models import LocationProductReference
from dojo.models import (
    Dojo_User,
    Endpoint,
    Endpoint_Status,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
)
from dojo.url.models import URL

from .dojo_test_case import DojoTestCase

LOCATIONS_ON = "dojo.finding.services.locations_enabled"


class ReassignTestDataMixin:

    """Two products in one product type, plus helpers to build a finding in either."""

    @classmethod
    def _make_products(cls, prefix):
        cls.product_type = Product_Type.objects.create(name=f"{prefix}_pt")
        cls.product_a = Product.objects.create(
            name=f"{prefix}_a", description="a", prod_type=cls.product_type,
        )
        cls.product_b = Product.objects.create(
            name=f"{prefix}_b", description="b", prod_type=cls.product_type,
        )
        cls.user = Dojo_User.objects.create_user(
            username=f"{prefix}_user", is_active=True, is_superuser=True,
        )

    def _test_in(self, product, name):
        now = timezone.now()
        engagement = Engagement.objects.create(
            name=name, product=product, target_start=now, target_end=now,
        )
        return Test.objects.create(
            engagement=engagement,
            scan_type="NPM Audit Scan",
            test_type=Test_Type.objects.get(name="NPM Audit Scan"),
            target_start=now,
            target_end=now,
        )

    def _finding_in(self, product, name):
        return Finding.objects.create(test=self._test_in(product, name), reporter=self.user)


class TestReassignFindingProductEndpoints(ReassignTestDataMixin, DojoTestCase):

    """
    ``reassign_finding_product_endpoints(findings, old_product, new_product)`` re-homes
    the endpoints/locations of exactly the findings it is given -- leaving the
    associations of findings that stayed behind intact.
    """

    @classmethod
    def setUpTestData(cls):
        cls._make_products("find_move")

    # --- Locations (V3) ------------------------------------------------------

    def test_rehomes_locations_to_destination_product(self):
        finding = self._finding_in(self.product_a, "eng-loc-1")
        url = URL(host="loc-one.example.com")
        url.save()
        location = url.location
        location.associate_with_finding(finding=finding)
        self.assertTrue(
            LocationProductReference.objects.filter(
                location=location, product=self.product_a,
            ).exists(),
        )

        # The move itself: re-point the finding, then re-home its locations.
        finding.test = self._test_in(self.product_b, "eng-loc-1-dest")
        finding.save()
        with patch(LOCATIONS_ON, return_value=True):
            reassign_finding_product_endpoints(
                Finding.objects.filter(id=finding.id), self.product_a, self.product_b,
            )

        self.assertTrue(
            LocationProductReference.objects.filter(
                location=location, product=self.product_b,
            ).exists(),
        )
        # Nothing is left in product A referencing it, so the stale association goes.
        self.assertFalse(
            LocationProductReference.objects.filter(
                location=location, product=self.product_a,
            ).exists(),
        )

    def test_keeps_source_association_when_another_finding_still_references_it(self):
        """
        The correctness-critical case: two findings in product A share one location and
        only one moves. Product A's association must SURVIVE, or the finding left behind
        loses its location.
        """
        mover = self._finding_in(self.product_a, "eng-shared-mover")
        stayer = self._finding_in(self.product_a, "eng-shared-stayer")
        url = URL(host="loc-shared.example.com")
        url.save()
        location = url.location
        location.associate_with_finding(finding=mover)
        location.associate_with_finding(finding=stayer)

        mover.test = self._test_in(self.product_b, "eng-shared-dest")
        mover.save()
        with patch(LOCATIONS_ON, return_value=True):
            reassign_finding_product_endpoints(
                Finding.objects.filter(id=mover.id), self.product_a, self.product_b,
            )

        # Destination gains the association ...
        self.assertTrue(
            LocationProductReference.objects.filter(
                location=location, product=self.product_b,
            ).exists(),
        )
        # ... and the source keeps it, because `stayer` still references the location.
        self.assertTrue(
            LocationProductReference.objects.filter(
                location=location, product=self.product_a,
            ).exists(),
        )

    # --- Endpoints (legacy v2) ----------------------------------------------
    # TODO: Delete these after the move to Locations

    def test_rehomes_endpoints_to_destination_product(self):
        finding = self._finding_in(self.product_a, "eng-ep-1")
        endpoint = Endpoint.from_uri("ep-one.example.com")
        endpoint.product = self.product_a
        endpoint.save()
        endpoint_status = Endpoint_Status.objects.create(finding=finding, endpoint=endpoint)

        finding.test = self._test_in(self.product_b, "eng-ep-1-dest")
        finding.save()
        with patch(LOCATIONS_ON, return_value=False):
            reassign_finding_product_endpoints(
                Finding.objects.filter(id=finding.id), self.product_a, self.product_b,
            )

        endpoint_status.refresh_from_db()
        self.assertEqual(self.product_b, endpoint_status.endpoint.product)
        # The source endpoint row itself is untouched.
        endpoint.refresh_from_db()
        self.assertEqual(self.product_a, endpoint.product)

    def test_shared_endpoint_is_rehomed_once_for_many_findings(self):
        """
        An endpoint shared by several moved findings must be get_or_create'd once in the
        destination product -- both for correctness (one row, not N) and to keep the
        move from degenerating into a per-finding query.
        """
        destination_test = self._test_in(self.product_b, "eng-ep-shared-dest")
        findings = [self._finding_in(self.product_a, f"eng-ep-shared-{i}") for i in range(3)]
        endpoint = Endpoint.from_uri("ep-shared.example.com")
        endpoint.product = self.product_a
        endpoint.save()
        for finding in findings:
            Endpoint_Status.objects.create(finding=finding, endpoint=endpoint)

        for finding in findings:
            finding.test = destination_test
            finding.save()
        with patch(LOCATIONS_ON, return_value=False):
            reassign_finding_product_endpoints(
                Finding.objects.filter(id__in=[f.id for f in findings]),
                self.product_a,
                self.product_b,
            )

        # Assert on the product rather than on a parsed field: Endpoint.from_uri() puts a
        # bare hostname in `path` (host stays None), so filtering by host proves nothing.
        self.assertEqual(
            1,
            Endpoint.objects.filter(product=self.product_b).count(),
            "the shared endpoint should be created exactly once in the destination",
        )
        for status in Endpoint_Status.objects.filter(finding__in=findings):
            self.assertEqual(self.product_b, status.endpoint.product)

    # --- Shared behaviour ---------------------------------------------------

    def test_noop_when_source_and_destination_match(self):
        finding = self._finding_in(self.product_a, "eng-noop")
        with patch("dojo.finding.services.dojo_dispatch_task") as mock_dispatch:
            reassign_finding_product_endpoints(
                Finding.objects.filter(id=finding.id), self.product_a, self.product_a,
            )
        mock_dispatch.assert_not_called()

    def test_noop_when_no_findings_given(self):
        with patch("dojo.finding.services.dojo_dispatch_task") as mock_dispatch:
            reassign_finding_product_endpoints(
                Finding.objects.none(), self.product_a, self.product_b,
            )
        mock_dispatch.assert_not_called()

    def test_accepts_a_plain_list_of_findings(self):
        """The signature takes any iterable, not only a queryset."""
        finding = self._finding_in(self.product_a, "eng-list")
        finding.test = self._test_in(self.product_b, "eng-list-dest")
        finding.save()
        with patch(LOCATIONS_ON, return_value=False), \
                patch("dojo.finding.services.dojo_dispatch_task") as mock_dispatch:
            reassign_finding_product_endpoints([finding], self.product_a, self.product_b)
        graded = {call.args[1] for call in mock_dispatch.call_args_list}
        self.assertEqual({self.product_a.id, self.product_b.id}, graded)

    def test_recalculates_grade_for_both_products(self):
        finding = self._finding_in(self.product_a, "eng-grade")
        finding.test = self._test_in(self.product_b, "eng-grade-dest")
        finding.save()
        with patch("dojo.finding.services.dojo_dispatch_task") as mock_dispatch:
            reassign_finding_product_endpoints(
                Finding.objects.filter(id=finding.id), self.product_a, self.product_b,
            )
        graded = {call.args[1] for call in mock_dispatch.call_args_list}
        self.assertEqual({self.product_a.id, self.product_b.id}, graded)


class TestEngagementDelegatesToFindingReassign(ReassignTestDataMixin, DojoTestCase):

    """
    ``reassign_engagement_product_endpoints`` is now a thin wrapper over
    ``reassign_finding_product_endpoints``. These are the regression net for that
    refactor, at service level: the API-level equivalents in
    ``test_apiv2_engagement.py`` cannot run in a container where SECURE_SSL_REDIRECT
    is on (every request 301s), so the delegation would otherwise be unproven.
    """

    @classmethod
    def setUpTestData(cls):
        cls._make_products("eng_deleg")

    def _engagement_with_finding(self):
        now = timezone.now()
        engagement = Engagement.objects.create(
            name="eng_deleg_eng", product=self.product_a, target_start=now, target_end=now,
        )
        test = Test.objects.create(
            engagement=engagement,
            scan_type="NPM Audit Scan",
            test_type=Test_Type.objects.get(name="NPM Audit Scan"),
            target_start=now,
            target_end=now,
        )
        return engagement, Finding.objects.create(test=test, reporter=self.user)

    def test_engagement_move_still_rehomes_locations(self):
        engagement, finding = self._engagement_with_finding()
        url = URL(host="eng-deleg-loc.example.com")
        url.save()
        location = url.location
        location.associate_with_finding(finding=finding)

        # The engagement moves, carrying its findings with it.
        engagement.product = self.product_b
        engagement.save()
        with patch(LOCATIONS_ON, return_value=True):
            reassign_engagement_product_endpoints(engagement, self.product_a, self.product_b)

        self.assertTrue(
            LocationProductReference.objects.filter(
                location=location, product=self.product_b,
            ).exists(),
        )
        self.assertFalse(
            LocationProductReference.objects.filter(
                location=location, product=self.product_a,
            ).exists(),
        )

    # TODO: Delete this after the move to Locations
    def test_engagement_move_still_rehomes_endpoints(self):
        engagement, finding = self._engagement_with_finding()
        endpoint = Endpoint.from_uri("eng-deleg-ep.example.com")
        endpoint.product = self.product_a
        endpoint.save()
        endpoint_status = Endpoint_Status.objects.create(finding=finding, endpoint=endpoint)

        engagement.product = self.product_b
        engagement.save()
        with patch(LOCATIONS_ON, return_value=False):
            reassign_engagement_product_endpoints(engagement, self.product_a, self.product_b)

        endpoint_status.refresh_from_db()
        self.assertEqual(self.product_b, endpoint_status.endpoint.product)
        endpoint.refresh_from_db()
        self.assertEqual(self.product_a, endpoint.product)
