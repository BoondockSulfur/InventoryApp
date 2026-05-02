import pytest
from datetime import date, timedelta
from app import User, Item, Loan


class TestUserModel:
    def test_user_creation(self, db):
        """Test creating a user."""
        user = User(username='testuser', email='test@example.com', role='kunde')
        user.set_password('TestPass123!')
        db.session.add(user)
        db.session.commit()

        assert user.id is not None
        assert user.username == 'testuser'
        assert user.email == 'test@example.com'
        assert user.role == 'kunde'

    def test_password_hashing(self, db):
        """Test password hashing and verification."""
        user = User(username='testuser', email='test@example.com', role='kunde')
        password = 'TestPass123!'
        user.set_password(password)

        assert user.password_hash is not None
        assert user.password_hash != password
        assert user.check_password(password) is True
        assert user.check_password('wrongpassword') is False

    def test_reset_token(self, admin_user):
        """Test password reset token generation and verification."""
        token = admin_user.get_reset_token()
        assert token is not None

        verified_user = User.verify_reset_token(token)
        assert verified_user is not None
        assert verified_user.id == admin_user.id


class TestItemModel:
    def test_item_creation(self, db):
        """Test creating an item."""
        item = Item(
            name='Test Item',
            serial='SERIAL123',
            location='Storage',
            category='laptop',
            is_borrowed=False,
            defective=False
        )
        db.session.add(item)
        db.session.commit()

        assert item.id is not None
        assert item.name == 'Test Item'
        assert item.serial == 'SERIAL123'
        assert item.is_borrowed is False
        assert item.defective is False

    def test_item_unique_serial(self, db, test_item):
        """Test that serial numbers must be unique."""
        duplicate_item = Item(
            name='Another Item',
            serial=test_item.serial,  # Same serial
            location='Storage',
            category='laptop'
        )
        db.session.add(duplicate_item)

        with pytest.raises(Exception):
            db.session.commit()


class TestLoanModel:
    def test_loan_creation(self, db, admin_user, test_item):
        """Test creating a loan."""
        loan = Loan(
            item_id=test_item.id,
            borrower_id=admin_user.id,
            loan_date=date.today(),
            due_date=date.today() + timedelta(days=7)
        )
        db.session.add(loan)
        db.session.commit()

        assert loan.id is not None
        assert loan.item_id == test_item.id
        assert loan.borrower_id == admin_user.id
        assert loan.return_date is None

    def test_loan_relationships(self, db, admin_user, test_item):
        """Test loan relationships with user and item."""
        loan = Loan(
            item_id=test_item.id,
            borrower_id=admin_user.id,
            loan_date=date.today(),
            due_date=date.today() + timedelta(days=7)
        )
        db.session.add(loan)
        db.session.commit()

        assert loan.borrower.username == admin_user.username
        assert loan.item.serial == test_item.serial
