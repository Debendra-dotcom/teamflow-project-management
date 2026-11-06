from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from rest_framework import status
from django.core.cache import cache

User = get_user_model()


class UserViewsTests(APITestCase):

    def setUp(self):
        cache.clear()
        # Users
        self.admin = User.objects.create_user(
            username="admin",
            email="admin@test.com",
            password="AdminPass123!",
            role="admin"
        )

        self.member = User.objects.create_user(
            username="member",
            email="member@test.com",
            password="MemberPass123!",
            role="member"
        )

        self.other_member = User.objects.create_user(
            username="other",
            email="other@test.com",
            password="OtherPass123!",
            role="member"
        )

        # URLs
        self.register_url = "/api/users/registration/"
        self.login_url = "/api/users/login/"
        self.logout_url = "/api/users/logout/"

        # ViewSet URL
        self.user_list_url = reverse("user-list")   # چون basename='user'
        self.user_detail_url = reverse("user-detail", kwargs={"pk": self.member.id})

    # ==================================================
    # REGISTER
    # ==================================================
    def test_register_success(self):
        payload = {
            "username": "newuser",
            "email": "newuser@test.com",
            "password": "NewPass123!",
        }
        res = self.client.post(self.register_url, payload, format="json")
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(username="newuser").exists())

    def test_register_fail_missing_fields(self):
        payload = {"username": "x"}
        res = self.client.post(self.register_url, payload, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_duplicate_username_and_password_confirmation(self):
        payload = {
            "username": "member", "email": "new@test.com",
            "password": "NewPass123!", "password_confirmation": "NewPass123!",
        }
        res = self.client.post(self.register_url, payload, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_mismatched_password_confirmation(self):
        payload = {
            "username": "newuser", "email": "new@test.com",
            "password": "NewPass123!", "password_confirmation": "Different123!",
        }
        res = self.client.post(self.register_url, payload, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    # ==================================================
    # LOGIN
    # ==================================================
    def test_login_success_returns_tokens(self):
        payload = {"username": "member", "password": "MemberPass123!"}
        res = self.client.post(self.login_url, payload, format="json")

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn("access", res.data)
        self.assertIn("refresh", res.data)

    def test_login_fail_wrong_password(self):
        payload = {"username": "member", "password": "wrong"}
        res = self.client.post(self.login_url, payload, format="json")

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_token_endpoints_and_authenticated_access(self):
        pair = self.client.post("/api/token/", {
            "username": "member", "password": "MemberPass123!",
        }, format="json")
        self.assertEqual(pair.status_code, status.HTTP_200_OK)
        self.assertIn("access", pair.data)
        self.assertIn("refresh", pair.data)

        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + pair.data["access"])
        protected = self.client.get(self.user_list_url)
        self.assertEqual(protected.status_code, status.HTTP_200_OK)
        self.client.credentials()
        self.assertEqual(self.client.get(self.user_list_url).status_code, status.HTTP_401_UNAUTHORIZED)

        refreshed = self.client.post("/api/token/refresh/", {
            "refresh": pair.data["refresh"],
        }, format="json")
        self.assertEqual(refreshed.status_code, status.HTTP_200_OK)
        self.assertIn("access", refreshed.data)

    def test_login_fail_inactive_user(self):
        self.member.is_active = False
        self.member.save()

        payload = {"username": "member", "password": "MemberPass123!"}
        res = self.client.post(self.login_url, payload, format="json")

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    # ==================================================
    # LOGOUT
    # ==================================================
    def test_logout_requires_auth(self):
        res = self.client.post(self.logout_url, {}, format="json")
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_success_blacklists_token(self):
        # login first
        login_payload = {"username": "member", "password": "MemberPass123!"}
        login_res = self.client.post(self.login_url, login_payload, format="json")
        refresh_token = login_res.data["refresh"]

        # authenticate
        self.client.force_authenticate(user=self.member)

        logout_payload = {"refresh": refresh_token}
        res = self.client.post(self.logout_url, logout_payload, format="json")

        self.assertEqual(res.status_code, status.HTTP_205_RESET_CONTENT)
        refresh_res = self.client.post("/api/token/refresh/", {
            "refresh": refresh_token,
        }, format="json")
        self.assertEqual(refresh_res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_fail_invalid_token(self):
        self.client.force_authenticate(user=self.member)
        payload = {"refresh": "invalid.token.value"}
        res = self.client.post(self.logout_url, payload, format="json")

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    # ==================================================
    # UserViewSet
    # ==================================================
    def test_user_viewset_list_requires_auth(self):
        res = self.client.get(self.user_list_url)
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_user_viewset_list_admin_sees_all_users(self):
        self.client.force_authenticate(user=self.admin)
        res = self.client.get(self.user_list_url)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        usernames = [u["username"] for u in res.data]
        self.assertIn("admin", usernames)
        self.assertIn("member", usernames)
        self.assertIn("other", usernames)

    def test_user_viewset_list_member_sees_only_self(self):
        self.client.force_authenticate(user=self.member)
        res = self.client.get(self.user_list_url)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(len(res.data), 1)
        self.assertEqual(res.data[0]["username"], "member")

    def test_user_viewset_retrieve_member_only_self(self):
        self.client.force_authenticate(user=self.member)

        # request own detail
        res = self.client.get(self.user_detail_url)
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data["username"], "member")

        # try retrieving another user
        other_url = reverse("user-detail", kwargs={"pk": self.other_member.id})
        res2 = self.client.get(other_url)

        # because queryset filters, likely 404
        self.assertIn(res2.status_code, [status.HTTP_404_NOT_FOUND, status.HTTP_403_FORBIDDEN])
