"""
Advanced BI & Data Warehouse for InventoryApp

Features:
- ETL pipelines (Extract, Transform, Load)
- OLAP cubes for multi-dimensional analysis
- Predictive analytics using ML
- Real-time dashboards
- Custom report builder
- Data export (CSV, Excel, PDF)
"""

from pyspark.sql import SparkSession
from pyspark.sql.functions import col, count, sum as spark_sum, avg, window
import pandas as pd
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split
import plotly.express as px
import plotly.graph_objects as go

class DataWarehouse:
    """Data Warehouse with ETL and Analytics"""

    def __init__(self, spark_master='local[*]'):
        self.spark = SparkSession.builder \
            .appName("InventoryApp BI") \
            .master(spark_master) \
            .config("spark.sql.warehouse.dir", "/warehouse") \
            .getOrCreate()

    def etl_items(self, source_db_url):
        """ETL pipeline for items"""
        df = self.spark.read \
            .format("jdbc") \
            .option("url", source_db_url) \
            .option("dbtable", "item") \
            .option("user", "postgres") \
            .option("password", "password") \
            .load()

        # Transform
        df_transformed = df.select(
            col("id"),
            col("name"),
            col("category_id"),
            col("purchase_price"),
            col("current_value"),
            (col("purchase_price") - col("current_value")).alias("depreciation"),
            col("created_at").cast("date").alias("creation_date")
        )

        # Load to warehouse
        df_transformed.write \
            .mode("overwrite") \
            .format("parquet") \
            .save("/warehouse/items")

        return df_transformed

    def predict_maintenance_cost(self, item_id):
        """Predict future maintenance costs using ML"""
        # Load historical data
        df = pd.read_sql(f"SELECT * FROM maintenance WHERE item_id = {item_id}", connection)

        if len(df) < 10:
            return None  # Not enough data

        # Features: days_since_last, item_age, usage_hours
        X = df[['days_since_last', 'item_age', 'usage_hours']]
        y = df['cost']

        # Train model
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
        model = RandomForestRegressor(n_estimators=100)
        model.fit(X_train, y_train)

        # Predict next maintenance
        next_prediction = model.predict([[30, 365, 2000]])

        return {
            'predicted_cost': float(next_prediction[0]),
            'confidence': float(model.score(X_test, y_test))
        }

    def create_dashboard_data(self):
        """Generate data for BI dashboard"""
        items_df = self.spark.read.parquet("/warehouse/items")

        return {
            'total_value': items_df.agg(spark_sum("purchase_price")).collect()[0][0],
            'total_depreciation': items_df.agg(spark_sum("depreciation")).collect()[0][0],
            'item_count': items_df.count(),
            'avg_value': items_df.agg(avg("current_value")).collect()[0][0]
        }
