# -*- coding: utf-8 -*-
"""
GraphQL Schema for InventoryApp
Provides flexible queries and mutations for the inventory system
"""

try:
    import graphene
    from graphene import relay
    from graphene_sqlalchemy import SQLAlchemyObjectType, SQLAlchemyConnectionField
    GRAPHQL_AVAILABLE = True
except ImportError:
    GRAPHQL_AVAILABLE = False
    print("⚠️  GraphQL libraries not available")

if GRAPHQL_AVAILABLE:
    from flask_login import current_user
    from app import db, Item, User, Loan, Category, Location, Company, Team

    # ─── Auth Helper ─────────────────────────────────────────────────────

    def require_auth(info):
        """Raise exception if user is not authenticated"""
        if not current_user or not current_user.is_authenticated:
            raise Exception("Authentication required")

    def require_admin(info):
        """Raise exception if user is not admin"""
        require_auth(info)
        if not current_user.is_admin:
            raise Exception("Admin permission required")

    # ─── GraphQL Object Types ─────────────────────────────────────────────

    class ItemType(SQLAlchemyObjectType):
        class Meta:
            model = Item
            interfaces = (relay.Node,)

    class UserType(SQLAlchemyObjectType):
        class Meta:
            model = User
            interfaces = (relay.Node,)
            exclude_fields = ('password_hash',)  # Never expose password hash

    class LoanType(SQLAlchemyObjectType):
        class Meta:
            model = Loan
            interfaces = (relay.Node,)

    class CategoryType(SQLAlchemyObjectType):
        class Meta:
            model = Category
            interfaces = (relay.Node,)

    class LocationType(SQLAlchemyObjectType):
        class Meta:
            model = Location
            interfaces = (relay.Node,)

    class CompanyType(SQLAlchemyObjectType):
        class Meta:
            model = Company
            interfaces = (relay.Node,)

    class TeamType(SQLAlchemyObjectType):
        class Meta:
            model = Team
            interfaces = (relay.Node,)

    # ─── Queries ──────────────────────────────────────────────────────────

    class Query(graphene.ObjectType):
        node = relay.Node.Field()

        # Items
        all_items = SQLAlchemyConnectionField(ItemType.connection)
        item = graphene.Field(ItemType, id=graphene.Int())
        items_by_category = graphene.List(ItemType, category_id=graphene.Int())
        items_by_location = graphene.List(ItemType, location_id=graphene.Int())
        available_items = graphene.List(ItemType)
        borrowed_items = graphene.List(ItemType)
        defective_items = graphene.List(ItemType)

        # Users
        all_users = SQLAlchemyConnectionField(UserType.connection)
        user = graphene.Field(UserType, id=graphene.Int())

        # Loans
        all_loans = SQLAlchemyConnectionField(LoanType.connection)
        loan = graphene.Field(LoanType, id=graphene.Int())
        active_loans = graphene.List(LoanType)
        overdue_loans = graphene.List(LoanType)

        # Categories & Locations
        all_categories = graphene.List(CategoryType)
        all_locations = graphene.List(LocationType)

        # Companies & Teams
        all_companies = graphene.List(CompanyType)
        all_teams = graphene.List(TeamType)

        # Resolvers — all require authentication
        def resolve_item(self, info, id):
            require_auth(info)
            return db.session.get(Item, id)

        def resolve_items_by_category(self, info, category_id):
            require_auth(info)
            return Item.query.filter_by(category_id=category_id).all()

        def resolve_items_by_location(self, info, location_id):
            require_auth(info)
            return Item.query.filter_by(location_id=location_id).all()

        def resolve_available_items(self, info):
            require_auth(info)
            return Item.query.filter_by(is_borrowed=False, defective=False).all()

        def resolve_borrowed_items(self, info):
            require_auth(info)
            return Item.query.filter_by(is_borrowed=True).all()

        def resolve_defective_items(self, info):
            require_auth(info)
            return Item.query.filter_by(defective=True).all()

        def resolve_user(self, info, id):
            require_auth(info)
            return db.session.get(User, id)

        def resolve_loan(self, info, id):
            require_auth(info)
            return db.session.get(Loan, id)

        def resolve_active_loans(self, info):
            require_auth(info)
            from datetime import datetime
            return Loan.query.filter(
                Loan.return_date.is_(None)
            ).all()

        def resolve_overdue_loans(self, info):
            require_auth(info)
            from datetime import datetime
            return Loan.query.filter(
                Loan.return_date.is_(None),
                Loan.due_date < datetime.utcnow()
            ).all()

        def resolve_all_categories(self, info):
            require_auth(info)
            return Category.query.all()

        def resolve_all_locations(self, info):
            require_auth(info)
            return Location.query.all()

        def resolve_all_companies(self, info):
            require_auth(info)
            return Company.query.all()

        def resolve_all_teams(self, info):
            require_auth(info)
            return Team.query.all()

    # ─── Mutations ────────────────────────────────────────────────────────

    class CreateItem(graphene.Mutation):
        class Arguments:
            name = graphene.String(required=True)
            description = graphene.String()
            serial = graphene.String()
            category_id = graphene.Int()
            location_id = graphene.Int()
            quantity = graphene.Int()

        item = graphene.Field(lambda: ItemType)
        ok = graphene.Boolean()

        def mutate(self, info, name, description=None, serial=None,
                   category_id=None, location_id=None, quantity=1):
            require_auth(info)
            item = Item(
                name=name,
                description=description,
                serial=serial,
                category_id=category_id,
                location_id=location_id,
                quantity=quantity
            )
            db.session.add(item)
            db.session.commit()
            return CreateItem(item=item, ok=True)

    class UpdateItem(graphene.Mutation):
        class Arguments:
            id = graphene.Int(required=True)
            name = graphene.String()
            description = graphene.String()
            serial = graphene.String()
            category_id = graphene.Int()
            location_id = graphene.Int()
            quantity = graphene.Int()
            defective = graphene.Boolean()

        item = graphene.Field(lambda: ItemType)
        ok = graphene.Boolean()

        def mutate(self, info, id, **kwargs):
            require_auth(info)
            item = db.session.get(Item, id)
            if not item:
                return UpdateItem(item=None, ok=False)

            for key, value in kwargs.items():
                if value is not None:
                    setattr(item, key, value)

            db.session.commit()
            return UpdateItem(item=item, ok=True)

    class DeleteItem(graphene.Mutation):
        class Arguments:
            id = graphene.Int(required=True)

        ok = graphene.Boolean()

        def mutate(self, info, id):
            require_admin(info)
            item = db.session.get(Item, id)
            if not item:
                return DeleteItem(ok=False)

            db.session.delete(item)
            db.session.commit()
            return DeleteItem(ok=True)

    class CreateLoan(graphene.Mutation):
        class Arguments:
            item_id = graphene.Int(required=True)
            borrower_id = graphene.Int(required=True)
            due_date = graphene.String(required=True)

        loan = graphene.Field(lambda: LoanType)
        ok = graphene.Boolean()

        def mutate(self, info, item_id, borrower_id, due_date):
            require_auth(info)
            from datetime import datetime

            item = db.session.get(Item, item_id)
            if not item or item.is_borrowed:
                return CreateLoan(loan=None, ok=False)

            loan = Loan(
                item_id=item_id,
                borrower_id=borrower_id,
                loan_date=datetime.utcnow(),
                due_date=datetime.fromisoformat(due_date)
            )
            item.is_borrowed = True

            db.session.add(loan)
            db.session.commit()
            return CreateLoan(loan=loan, ok=True)

    class ReturnLoan(graphene.Mutation):
        class Arguments:
            loan_id = graphene.Int(required=True)

        loan = graphene.Field(lambda: LoanType)
        ok = graphene.Boolean()

        def mutate(self, info, loan_id):
            require_auth(info)
            from datetime import datetime

            loan = db.session.get(Loan, loan_id)
            if not loan or loan.return_date:
                return ReturnLoan(loan=None, ok=False)

            loan.return_date = datetime.utcnow()
            loan.item.is_borrowed = False

            db.session.commit()
            return ReturnLoan(loan=loan, ok=True)

    class Mutation(graphene.ObjectType):
        create_item = CreateItem.Field()
        update_item = UpdateItem.Field()
        delete_item = DeleteItem.Field()
        create_loan = CreateLoan.Field()
        return_loan = ReturnLoan.Field()

    # ─── Schema ───────────────────────────────────────────────────────────

    schema = graphene.Schema(query=Query, mutation=Mutation)

else:
    schema = None
