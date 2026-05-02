"""
Machine Learning Service for AI-Powered Features
- Smart categorization
- Predictive maintenance alerts
- Usage pattern analysis
"""

import os
import logging
import pickle
from datetime import datetime, timedelta
from collections import defaultdict, Counter

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

logger = logging.getLogger(__name__)


class MLService:
    """Service for ML-powered features"""

    def __init__(self, app=None):
        self.app = app
        self.models = {}
        self.vectorizers = {}
        self.model_dir = 'ml_models'

        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize ML service"""
        self.app = app

        # Create models directory if it doesn't exist
        if not os.path.exists(self.model_dir):
            os.makedirs(self.model_dir)

        # Load existing models
        self._load_models()

    def _load_models(self):
        """Load pre-trained models from disk"""
        try:
            categorizer_path = os.path.join(self.model_dir, 'categorizer.pkl')
            vectorizer_path = os.path.join(self.model_dir, 'categorizer_vectorizer.pkl')

            if os.path.exists(categorizer_path) and os.path.exists(vectorizer_path):
                self.models['categorizer'] = joblib.load(categorizer_path)
                self.vectorizers['categorizer'] = joblib.load(vectorizer_path)
                logger.info("Loaded categorization model")
        except Exception as e:
            logger.error(f"Error loading models: {e}")

    def _save_model(self, model_name, model, vectorizer=None):
        """Save a trained model to disk"""
        try:
            model_path = os.path.join(self.model_dir, f'{model_name}.pkl')
            joblib.dump(model, model_path)

            if vectorizer:
                vectorizer_path = os.path.join(self.model_dir, f'{model_name}_vectorizer.pkl')
                joblib.dump(vectorizer, vectorizer_path)

            logger.info(f"Saved model: {model_name}")
            return True
        except Exception as e:
            logger.error(f"Error saving model {model_name}: {e}")
            return False

    def train_categorizer(self, items):
        """
        Train a model to predict item categories based on name and description

        Args:
            items: List of Item objects with name, description, and category

        Returns:
            Dict with training metrics
        """
        try:
            # Prepare training data
            X_texts = []
            y_labels = []

            for item in items:
                if not item.category:
                    continue

                # Combine name and description as features
                text = f"{item.name} {item.description or ''}"
                X_texts.append(text)
                y_labels.append(item.category)

            if len(X_texts) < 10:
                logger.warning("Not enough labeled data to train categorizer (need at least 10)")
                return {'success': False, 'error': 'Insufficient training data'}

            # Create TF-IDF features
            vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 2))
            X = vectorizer.fit_transform(X_texts)

            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y_labels, test_size=0.2, random_state=42
            )

            # Train Naive Bayes classifier (works well with text)
            model = MultinomialNB()
            model.fit(X_train, y_train)

            # Evaluate
            y_pred = model.predict(X_test)
            accuracy = model.score(X_test, y_test)

            # Save model
            self.models['categorizer'] = model
            self.vectorizers['categorizer'] = vectorizer
            self._save_model('categorizer', model, vectorizer)

            logger.info(f"Trained categorizer with accuracy: {accuracy:.2f}")

            return {
                'success': True,
                'accuracy': accuracy,
                'num_categories': len(set(y_labels)),
                'num_samples': len(X_texts)
            }
        except Exception as e:
            logger.error(f"Error training categorizer: {e}")
            return {'success': False, 'error': str(e)}

    def predict_category(self, item_name, item_description=''):
        """
        Predict category for an item

        Args:
            item_name: Name of the item
            item_description: Description of the item

        Returns:
            Dict with predicted category and confidence
        """
        if 'categorizer' not in self.models or 'categorizer' not in self.vectorizers:
            return {'predicted_category': None, 'confidence': 0.0, 'suggestions': []}

        try:
            text = f"{item_name} {item_description}"
            X = self.vectorizers['categorizer'].transform([text])

            # Get prediction
            predicted_category = self.models['categorizer'].predict(X)[0]

            # Get probability scores for all categories
            probas = self.models['categorizer'].predict_proba(X)[0]
            classes = self.models['categorizer'].classes_

            # Get top 3 suggestions with confidence scores
            top_indices = np.argsort(probas)[-3:][::-1]
            suggestions = [
                {'category': classes[i], 'confidence': float(probas[i])}
                for i in top_indices
            ]

            return {
                'predicted_category': predicted_category,
                'confidence': float(max(probas)),
                'suggestions': suggestions
            }
        except Exception as e:
            logger.error(f"Error predicting category: {e}")
            return {'predicted_category': None, 'confidence': 0.0, 'suggestions': []}

    def analyze_usage_patterns(self, items, loans):
        """
        Analyze usage patterns for items

        Args:
            items: List of Item objects
            loans: List of Loan objects

        Returns:
            Dict with usage insights
        """
        try:
            # Calculate metrics per item
            item_metrics = defaultdict(lambda: {
                'loan_count': 0,
                'total_days': 0,
                'avg_duration': 0,
                'last_loan': None,
                'popular': False
            })

            for loan in loans:
                item_id = loan.item_id
                item_metrics[item_id]['loan_count'] += 1

                if loan.return_date and loan.loan_date:
                    days = (loan.return_date - loan.loan_date).days
                    item_metrics[item_id]['total_days'] += days

                if loan.loan_date:
                    if not item_metrics[item_id]['last_loan'] or loan.loan_date > item_metrics[item_id]['last_loan']:
                        item_metrics[item_id]['last_loan'] = loan.loan_date

            # Calculate averages and identify patterns
            for item_id, metrics in item_metrics.items():
                if metrics['loan_count'] > 0:
                    metrics['avg_duration'] = metrics['total_days'] / metrics['loan_count']

            # Identify popular items (top 20% by loan count)
            if item_metrics:
                loan_counts = [m['loan_count'] for m in item_metrics.values()]
                threshold = np.percentile(loan_counts, 80)

                for item_id, metrics in item_metrics.items():
                    if metrics['loan_count'] >= threshold:
                        metrics['popular'] = True

            # Find items that haven't been loaned recently
            inactive_threshold = datetime.utcnow() - timedelta(days=180)
            inactive_items = []

            for item_id, metrics in item_metrics.items():
                if metrics['last_loan'] and metrics['last_loan'] < inactive_threshold:
                    inactive_items.append(item_id)

            return {
                'total_items_analyzed': len(items),
                'items_with_loans': len(item_metrics),
                'popular_items': [id for id, m in item_metrics.items() if m['popular']],
                'inactive_items': inactive_items,
                'avg_loan_duration': np.mean([m['avg_duration'] for m in item_metrics.values() if m['avg_duration'] > 0]) if item_metrics else 0,
                'item_metrics': dict(item_metrics)
            }
        except Exception as e:
            logger.error(f"Error analyzing usage patterns: {e}")
            return {}

    def predict_maintenance(self, items, maintenance_history):
        """
        Predict which items might need maintenance soon

        Args:
            items: List of Item objects
            maintenance_history: List of maintenance records

        Returns:
            List of items that might need maintenance with confidence scores
        """
        try:
            predictions = []

            # Calculate maintenance frequency per item
            item_maintenance = defaultdict(list)
            for record in maintenance_history:
                if hasattr(record, 'item_id') and hasattr(record, 'date'):
                    item_maintenance[record.item_id].append(record.date)

            for item in items:
                if item.id not in item_maintenance:
                    continue

                maintenance_dates = sorted(item_maintenance[item.id])

                if len(maintenance_dates) < 2:
                    continue

                # Calculate average interval between maintenance
                intervals = []
                for i in range(1, len(maintenance_dates)):
                    interval = (maintenance_dates[i] - maintenance_dates[i-1]).days
                    intervals.append(interval)

                avg_interval = np.mean(intervals)
                std_interval = np.std(intervals) if len(intervals) > 1 else 0

                # Predict next maintenance date
                last_maintenance = maintenance_dates[-1]
                days_since_last = (datetime.utcnow() - last_maintenance).days
                expected_next = avg_interval

                # Calculate confidence based on regularity
                confidence = 1.0 / (1.0 + std_interval / avg_interval) if avg_interval > 0 else 0.5

                # If approaching or past expected maintenance
                if days_since_last >= expected_next * 0.8:
                    priority = 'high' if days_since_last >= expected_next else 'medium'

                    predictions.append({
                        'item_id': item.id,
                        'item_name': item.name,
                        'days_since_last_maintenance': days_since_last,
                        'expected_interval': avg_interval,
                        'priority': priority,
                        'confidence': confidence,
                        'predicted_date': (last_maintenance + timedelta(days=avg_interval)).isoformat()
                    })

            # Sort by priority and days overdue
            predictions.sort(key=lambda x: (x['priority'] == 'high', x['days_since_last_maintenance']), reverse=True)

            return predictions
        except Exception as e:
            logger.error(f"Error predicting maintenance: {e}")
            return []

    def smart_search_reranking(self, search_results, user_history):
        """
        Re-rank search results based on user's history and preferences

        Args:
            search_results: List of items from search
            user_history: User's interaction history (loans, views, etc.)

        Returns:
            Re-ranked list of items
        """
        try:
            if not user_history or not search_results:
                return search_results

            # Calculate relevance scores
            scores = {}
            for item in search_results:
                score = 0

                # Boost items from categories the user frequently interacts with
                if hasattr(item, 'category'):
                    category_interactions = sum(1 for h in user_history if hasattr(h, 'category') and h.category == item.category)
                    score += category_interactions * 2

                # Boost items the user has loaned before
                if hasattr(item, 'id'):
                    previous_loans = sum(1 for h in user_history if hasattr(h, 'item_id') and h.item_id == item.id)
                    score += previous_loans * 3

                scores[item.id] = score

            # Re-rank by combining original order with personalization score
            reranked = sorted(search_results, key=lambda x: (scores.get(x.id, 0), -search_results.index(x)), reverse=True)

            return reranked
        except Exception as e:
            logger.error(f"Error in search reranking: {e}")
            return search_results

    def generate_recommendations(self, user, items, loans, limit=5):
        """
        Generate item recommendations for a user

        Args:
            user: User object
            items: List of all items
            loans: List of all loans
            limit: Number of recommendations to return

        Returns:
            List of recommended items
        """
        try:
            # Get user's loan history
            user_loans = [loan for loan in loans if loan.user_id == user.id]

            if not user_loans:
                # New user - recommend popular items
                item_popularity = Counter([loan.item_id for loan in loans])
                popular_item_ids = [item_id for item_id, _ in item_popularity.most_common(limit)]
                return [item for item in items if item.id in popular_item_ids]

            # Find categories and items user has borrowed
            user_categories = Counter([loan.item.category for loan in user_loans if hasattr(loan.item, 'category')])
            borrowed_item_ids = set([loan.item_id for loan in user_loans])

            recommendations = []

            # Recommend items from favorite categories that user hasn't borrowed
            for category, _ in user_categories.most_common(3):
                category_items = [item for item in items if hasattr(item, 'category') and item.category == category and item.id not in borrowed_item_ids]
                recommendations.extend(category_items[:limit])

            # If not enough recommendations, add popular items
            if len(recommendations) < limit:
                item_popularity = Counter([loan.item_id for loan in loans if loan.item_id not in borrowed_item_ids])
                for item_id, _ in item_popularity.most_common(limit - len(recommendations)):
                    item = next((i for i in items if i.id == item_id), None)
                    if item and item not in recommendations:
                        recommendations.append(item)

            return recommendations[:limit]
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
            return []


# Global instance
ml_service = MLService()
