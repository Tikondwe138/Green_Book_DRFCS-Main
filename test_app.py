import unittest
from app import app

class FlaskTest(unittest.TestCase):

    # Test for Chat Page
    def test_chat_page(self):
        tester = app.test_client(self)
        response = tester.get('/chat')
        self.assertEqual(response.status_code, 200)

    # Test for Fund Statistics Page
    def test_fund_statistics(self):
        tester = app.test_client(self)
        response = tester.get('/fund_statistics')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'"amounts":', response.data)  # Check for data presence

    # Test for Admin Dashboard
    def test_admin_dashboard(self):
        tester = app.test_client(self)
        response = tester.get('/admin_dashboard')
        self.assertEqual(response.status_code, 200)

    # Test for Real-Time Notifications
    def test_notifications(self):
        tester = app.test_client(self)
        response = tester.get('/notifications')
        self.assertEqual(response.status_code, 200)

    # Test for Fund Allocation Table
    def test_fund_allocation(self):
        tester = app.test_client(self)
        response = tester.get('/fund_allocation')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Funds Allocated', response.data)  # Check if table is rendered

if __name__ == '__main__':
    unittest.main()
