import numpy as np
from sklearn.ensemble import IsolationForest
from typing import List

class AIAnomalyDetector:
    """Class for detecting anomalous behavior using machine learning"""
    
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.features: List[List[float]] = []
    
    def extract_features(self, response):
        """Extract features from HTTP response for anomaly detection"""
        features = [
            len(response.text),
            len(response.headers),
            response.status,
            sum(1 for c in response.text if c.isupper()),
            response.text.count('error'),
            response.text.count('warning')
        ]
        self.features.append(features)
        return features
    
    def train_model(self):
        """Train anomaly detection model"""
        if len(self.features) > 0:
            X = np.array(self.features)
            self.model.fit(X)
    
    def detect_anomaly(self, features):
        """Detect anomalous responses"""
        if len(self.features) > 0:
            return self.model.predict([features])[0] == -1
        return False