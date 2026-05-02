# -*- coding: utf-8 -*-
"""
Analytics Module for InventoryApp
Generates interactive charts and statistics using Plotly
"""

try:
    import plotly
    import plotly.graph_objs as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    import json
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

from datetime import datetime, timedelta
from sqlalchemy import func

if PLOTLY_AVAILABLE:
    def generate_inventory_overview_chart(db, Item, Category):
        """
        Generate bar chart showing items per category
        """
        # Query items count per category
        category_stats = db.session.query(
            Category.name,
            func.count(Item.id).label('count')
        ).join(Item, Item.category_id == Category.id)\
         .group_by(Category.name)\
         .all()

        if not category_stats:
            return None

        categories = [stat[0] for stat in category_stats]
        counts = [stat[1] for stat in category_stats]

        fig = go.Figure(data=[
            go.Bar(
                x=categories,
                y=counts,
                marker_color='rgb(55, 83, 109)',
                text=counts,
                textposition='auto',
            )
        ])

        fig.update_layout(
            title='Items per Category',
            xaxis_title='Category',
            yaxis_title='Number of Items',
            template='plotly_white',
            height=400
        )

        return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    def generate_loan_timeline_chart(db, Loan):
        """
        Generate timeline chart showing loan activity over time
        """
        # Get loans from last 30 days
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        loans = db.session.query(
            func.date(Loan.loan_date).label('date'),
            func.count(Loan.id).label('count')
        ).filter(Loan.loan_date >= thirty_days_ago)\
         .group_by(func.date(Loan.loan_date))\
         .all()

        if not loans:
            return None

        dates = [loan[0] for loan in loans]
        counts = [loan[1] for loan in loans]

        fig = go.Figure(data=[
            go.Scatter(
                x=dates,
                y=counts,
                mode='lines+markers',
                line=dict(color='rgb(55, 83, 109)', width=3),
                marker=dict(size=8)
            )
        ])

        fig.update_layout(
            title='Loan Activity (Last 30 Days)',
            xaxis_title='Date',
            yaxis_title='Number of Loans',
            template='plotly_white',
            height=400
        )

        return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    def generate_item_status_pie_chart(db, Item):
        """
        Generate pie chart showing item status distribution
        """
        available = db.session.query(Item).filter_by(is_borrowed=False, defective=False).count()
        borrowed = db.session.query(Item).filter_by(is_borrowed=True).count()
        defective = db.session.query(Item).filter_by(defective=True).count()

        labels = ['Available', 'Borrowed', 'Defective']
        values = [available, borrowed, defective]
        colors = ['#2ecc71', '#3498db', '#e74c3c']

        fig = go.Figure(data=[
            go.Pie(
                labels=labels,
                values=values,
                marker=dict(colors=colors),
                hole=0.3,
                textinfo='label+percent+value'
            )
        ])

        fig.update_layout(
            title='Item Status Distribution',
            template='plotly_white',
            height=400
        )

        return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    def generate_location_heatmap(db, Item, Location):
        """
        Generate heatmap showing item distribution across locations
        """
        location_stats = db.session.query(
            Location.name,
            func.count(Item.id).label('count')
        ).join(Item, Item.location_id == Location.id)\
         .group_by(Location.name)\
         .all()

        if not location_stats:
            return None

        locations = [stat[0] for stat in location_stats]
        counts = [stat[1] for stat in location_stats]

        fig = go.Figure(data=[
            go.Bar(
                x=locations,
                y=counts,
                marker=dict(
                    color=counts,
                    colorscale='Viridis',
                    showscale=True,
                    colorbar=dict(title="Items")
                ),
                text=counts,
                textposition='auto',
            )
        ])

        fig.update_layout(
            title='Item Distribution by Location',
            xaxis_title='Location',
            yaxis_title='Number of Items',
            template='plotly_white',
            height=400
        )

        return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    def generate_overdue_loans_chart(db, Loan, User):
        """
        Generate bar chart showing overdue loans by user
        """
        from datetime import datetime

        overdue_stats = db.session.query(
            User.username,
            func.count(Loan.id).label('count')
        ).join(Loan, Loan.borrower_id == User.id)\
         .filter(Loan.return_date.is_(None))\
         .filter(Loan.due_date < datetime.utcnow())\
         .group_by(User.username)\
         .all()

        if not overdue_stats:
            # Return empty chart
            fig = go.Figure()
            fig.add_annotation(
                text="No overdue loans",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False,
                font=dict(size=20)
            )
            fig.update_layout(
                title='Overdue Loans by User',
                template='plotly_white',
                height=400
            )
            return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

        users = [stat[0] for stat in overdue_stats]
        counts = [stat[1] for stat in overdue_stats]

        fig = go.Figure(data=[
            go.Bar(
                x=users,
                y=counts,
                marker_color='rgb(231, 76, 60)',
                text=counts,
                textposition='auto',
            )
        ])

        fig.update_layout(
            title='Overdue Loans by User',
            xaxis_title='User',
            yaxis_title='Number of Overdue Loans',
            template='plotly_white',
            height=400
        )

        return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    def generate_dashboard_charts(db, Item, Category, Location, Loan, User):
        """
        Generate all dashboard charts at once
        Returns dict with all chart JSONs
        """
        return {
            'inventory_overview': generate_inventory_overview_chart(db, Item, Category),
            'loan_timeline': generate_loan_timeline_chart(db, Loan),
            'item_status': generate_item_status_pie_chart(db, Item),
            'location_heatmap': generate_location_heatmap(db, Item, Location),
            'overdue_loans': generate_overdue_loans_chart(db, Loan, User)
        }

    def generate_custom_report_chart(data, chart_type, title, x_label, y_label):
        """
        Generate custom chart from provided data

        Args:
            data: List of dicts with 'x' and 'y' keys
            chart_type: 'bar', 'line', 'pie', 'scatter'
            title: Chart title
            x_label: X-axis label
            y_label: Y-axis label
        """
        x_values = [d['x'] for d in data]
        y_values = [d['y'] for d in data]

        if chart_type == 'bar':
            fig = go.Figure(data=[go.Bar(x=x_values, y=y_values)])
        elif chart_type == 'line':
            fig = go.Figure(data=[go.Scatter(x=x_values, y=y_values, mode='lines+markers')])
        elif chart_type == 'pie':
            fig = go.Figure(data=[go.Pie(labels=x_values, values=y_values)])
        elif chart_type == 'scatter':
            fig = go.Figure(data=[go.Scatter(x=x_values, y=y_values, mode='markers')])
        else:
            raise ValueError(f"Unsupported chart type: {chart_type}")

        fig.update_layout(
            title=title,
            xaxis_title=x_label if chart_type != 'pie' else None,
            yaxis_title=y_label if chart_type != 'pie' else None,
            template='plotly_white',
            height=400
        )

        return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

else:
    # Fallback functions when Plotly is not available
    def generate_inventory_overview_chart(*args, **kwargs):
        return None

    def generate_loan_timeline_chart(*args, **kwargs):
        return None

    def generate_item_status_pie_chart(*args, **kwargs):
        return None

    def generate_location_heatmap(*args, **kwargs):
        return None

    def generate_overdue_loans_chart(*args, **kwargs):
        return None

    def generate_dashboard_charts(*args, **kwargs):
        return {}

    def generate_custom_report_chart(*args, **kwargs):
        return None
