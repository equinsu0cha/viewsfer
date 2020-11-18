from unittest.mock import patch
from django.test import override_settings

from tacticalrmm.test import TacticalTestCase
from accounts.models import User


class TestAccounts(TacticalTestCase):
    def setUp(self):
        self.client_setup()
        self.bob = User(username="bob")
        self.bob.set_password("hunter2")
        self.bob.save()

    def test_check_creds(self):
        url = "/checkcreds/"

        data = {"username": "bob", "password": "hunter2"}
        r = self.client.post(url, data, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertIn("totp", r.data.keys())
        self.assertEqual(r.data["totp"], "totp not set")

        data = {"username": "bob", "password": "a3asdsa2314"}
        r = self.client.post(url, data, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data, "bad credentials")

        data = {"username": "billy", "password": "hunter2"}
        r = self.client.post(url, data, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data, "bad credentials")

        self.bob.totp_key = "AB5RI6YPFTZAS52G"
        self.bob.save()
        data = {"username": "bob", "password": "hunter2"}
        r = self.client.post(url, data, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, "ok")

    @patch("pyotp.TOTP.verify")
    def test_login_view(self, mock_verify):
        url = "/login/"

        mock_verify.return_value = True
        data = {"username": "bob", "password": "hunter2", "twofactor": "123456"}
        r = self.client.post(url, data, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertIn("expiry", r.data.keys())
        self.assertIn("token", r.data.keys())

        mock_verify.return_value = False
        r = self.client.post(url, data, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data, "bad credentials")

        mock_verify.return_value = True
        data = {"username": "bob", "password": "asd234234asd", "twofactor": "123456"}
        r = self.client.post(url, data, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("non_field_errors", r.data.keys())

    @override_settings(DEBUG=True)
    @patch("pyotp.TOTP.verify")
    def test_debug_login_view(self, mock_verify):
        url = "/login/"
        mock_verify.return_value = True

        data = {"username": "bob", "password": "hunter2", "twofactor": "sekret"}
        r = self.client.post(url, data, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertIn("expiry", r.data.keys())
        self.assertIn("token", r.data.keys())


class TestGetAddUsers(TacticalTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def test_get(self):
        url = "/accounts/users/"
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)

        assert any(i["username"] == "john" for i in r.json())

        assert not any(
            i["username"] == "71AHC-AA813-HH1BC-AAHH5-00013|DESKTOP-TEST123"
            for i in r.json()
        )

        self.check_not_authenticated("get", url)

    def test_post_add_duplicate(self):
        url = "/accounts/users/"
        data = {
            "username": "john",
            "password": "askdjaskdj",
            "email": "john@example.com",
            "first_name": "",
            "last_name": "",
        }
        r = self.client.post(url, data, format="json")
        self.assertEqual(r.status_code, 400)

    def test_post_add_new(self):
        url = "/accounts/users/"
        data = {
            "username": "jane",
            "password": "ASd1234asd",
            "email": "jane@example.com",
            "first_name": "",
            "last_name": "",
        }
        r = self.client.post(url, data, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, "jane")

        self.check_not_authenticated("post", url)


class GetUpdateDeleteUser(TacticalTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def test_get(self):
        url = f"/accounts/{self.john.pk}/users/"
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["username"], "john")

        url = "/accounts/2345/users/"
        r = self.client.get(url)
        self.assertEqual(r.status_code, 404)

        self.check_not_authenticated("get", url)

    def test_put(self):
        url = f"/accounts/{self.john.pk}/users/"
        data = {
            "id": self.john.pk,
            "username": "john",
            "email": "johndoe@xlawgaming.com",
            "first_name": "John",
            "last_name": "Doe",
        }
        r = self.client.put(url, data, format="json")
        self.assertEqual(r.status_code, 200)

        data["email"] = "aksjdaksjdklasjdlaksdj"
        r = self.client.put(url, data, format="json")
        self.assertEqual(r.status_code, 400)

        self.check_not_authenticated("put", url)

    def test_delete(self):
        url = f"/accounts/{self.john.pk}/users/"
        r = self.client.delete(url)
        self.assertEqual(r.status_code, 200)

        url = f"/accounts/893452/users/"
        r = self.client.delete(url)
        self.assertEqual(r.status_code, 404)

        self.check_not_authenticated("delete", url)


class TestUserAction(TacticalTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def test_post(self):
        url = "/accounts/users/reset/"
        data = {"id": self.john.pk, "password": "3ASDjh2345kJA!@#)#@__123"}
        r = self.client.post(url, data, format="json")
        self.assertEqual(r.status_code, 200)

        data["id"] = 43924
        r = self.client.post(url, data, format="json")
        self.assertEqual(r.status_code, 404)

        self.check_not_authenticated("post", url)

    def test_put(self):
        url = "/accounts/users/reset/"
        data = {"id": self.john.pk}
        r = self.client.put(url, data, format="json")
        self.assertEqual(r.status_code, 200)

        user = User.objects.get(pk=self.john.pk)
        self.assertEqual(user.totp_key, "")

        self.check_not_authenticated("put", url)

    def test_darkmode(self):
        url = "/accounts/users/ui/"
        data = {"dark_mode": False}
        r = self.client.patch(url, data, format="json")
        self.assertEqual(r.status_code, 200)

        self.check_not_authenticated("patch", url)


class TestTOTPSetup(TacticalTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def test_post(self):
        url = "/accounts/users/setup_totp/"
        r = self.client.post(url)
        self.assertEqual(r.status_code, 200)
        self.assertIn("username", r.json().keys())
        self.assertIn("totp_key", r.json().keys())
        self.assertIn("qr_url", r.json().keys())
        self.assertEqual("john", r.json()["username"])
        self.assertIn("otpauth://totp", r.json()["qr_url"])

        self.check_not_authenticated("post", url)

    def test_post_totp_set(self):
        url = "/accounts/users/setup_totp/"
        self.john.totp_key = "AB5RI6YPFTZAS52G"
        self.john.save()

        r = self.client.post(url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, "totp token already set")
