import pickle
import os
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

class MLModel:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.model_path = 'data/models/ids_model.pkl'
        self.scaler_path = 'data/models/scaler.pkl'
        
    def load_model(self):
        """Load pre-trained model"""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                with open(self.scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                print("[*] ML Model loaded successfully")
                return True
        except:
            print("[!] Could not load ML model")
        return False
    
    def train_model(self, features=None, labels=None):
        """Train or retrain the model"""
        if features is None or labels is None:
            # Generate synthetic data for demonstration
            features, labels = self.generate_training_data()
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels, test_size=0.2, random_state=42
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train Random Forest
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.model.fit(X_train_scaled, y_train)
        
        # Save model
        os.makedirs('data/models', exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
        with open(self.scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        
        accuracy = self.model.score(X_test_scaled, y_test)
        print(f"[*] Model trained with accuracy: {accuracy:.2f}")
        
        return accuracy
    
    def predict(self, features):
        """Predict if packet is attack"""
        if self.model is None:
            return None
        
        # Convert features to array
        feature_vector = self.extract_ml_features(features)
        if feature_vector is not None:
            # Scale features
            feature_vector_scaled = self.scaler.transform([feature_vector])
            prediction = self.model.predict(feature_vector_scaled)
            if prediction[0] == 1:  # Attack detected
                return "ML Detected Attack"
        
        return None
    
    def extract_ml_features(self, packet_features):
        """Extract features for ML model"""
        try:
            features = [
                packet_features.get('src_port', 0) or 0,
                packet_features.get('dst_port', 0) or 0,
                packet_features.get('protocol', 0) or 0,
                len(str(packet_features))  # Simple feature
            ]
            return features
        except:
            return None
    
    def generate_training_data(self):
        """Generate synthetic training data"""
        np.random.seed(42)
        n_samples = 1000
        
        # Normal traffic features
        normal_features = np.random.normal(50, 10, (n_samples, 4))
        normal_labels = np.zeros(n_samples)
        
        # Attack traffic features
        attack_features = np.random.normal(150, 30, (n_samples, 4))
        attack_labels = np.ones(n_samples)
        
        # Combine
        features = np.vstack([normal_features, attack_features])
        labels = np.hstack([normal_labels, attack_labels])
        
        return features, labels
