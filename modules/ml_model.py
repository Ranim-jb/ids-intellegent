# Import pickle for model serialization
import pickle
# Import os for file operations
import os
# Import numpy for numerical operations
import numpy as np

# Try to import scikit-learn components, handle if not available
try:
    from sklearn.ensemble import RandomForestClassifier  # ML algorithm
    from sklearn.model_selection import train_test_split  # Data splitting
    from sklearn.preprocessing import StandardScaler  # Feature scaling
    SKLEARN_AVAILABLE = True  # Flag indicating sklearn availability
except ImportError:
    SKLEARN_AVAILABLE = False
    print("[!] scikit-learn not available. ML features disabled.")

# Machine Learning model class for anomaly detection
class MLModel:
    def __init__(self):
        # Initialize model and scaler
        self.model = None
        self.scaler = StandardScaler() if SKLEARN_AVAILABLE else None
        # File paths for saving/loading model
        self.model_path = 'data/models/ids_model.pkl'
        self.scaler_path = 'data/models/scaler.pkl'

    def load_model(self):
        """Load pre-trained machine learning model from disk"""
        # Check if scikit-learn is available
        if not SKLEARN_AVAILABLE:
            print("[!] scikit-learn not available. Skipping model load.")
            return False
        try:
            # Check if model files exist
            if os.path.exists(self.model_path):
                # Load the trained model
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                # Load the feature scaler
                with open(self.scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                print("[*] ML Model loaded successfully")
                return True
        except:
            print("[!] Could not load ML model")
        return False

    def train_model(self, features=None, labels=None):
        """Train or retrain the machine learning model"""
        # Check if scikit-learn is available
        if not SKLEARN_AVAILABLE:
            print("[!] scikit-learn not available. Cannot train model.")
            return False

        # If no data provided, generate synthetic training data
        if features is None or labels is None:
            # Generate synthetic data for demonstration
            features, labels = self.generate_training_data()

        # Split data into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(
            features, labels, test_size=0.2, random_state=42
        )

        # Scale features using StandardScaler
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # Train Random Forest classifier
        self.model = RandomForestClassifier(
            n_estimators=100,  # Number of trees
            max_depth=10,  # Maximum tree depth
            random_state=42  # For reproducibility
        )
        self.model.fit(X_train_scaled, y_train)

        # Save trained model and scaler
        os.makedirs('data/models', exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
        with open(self.scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)

        # Calculate and return model accuracy
        accuracy = self.model.score(X_test_scaled, y_test)
        print(f"[*] Model trained with accuracy: {accuracy:.2f}")

        return accuracy

    def predict(self, features):
        """Predict if packet features indicate an attack"""
        # Check if model is loaded
        if self.model is None:
            return None

        # Extract features for ML prediction
        feature_vector = self.extract_ml_features(features)
        if feature_vector is not None:
            # Scale features using trained scaler
            feature_vector_scaled = self.scaler.transform([feature_vector])
            # Make prediction
            prediction = self.model.predict(feature_vector_scaled)
            if prediction[0] == 1:  # Attack detected (1 = attack, 0 = normal)
                return "ML Detected Attack"

        return None

    def extract_ml_features(self, packet_features):
        """Extract numerical features from packet data for ML model"""
        try:
            # Create feature vector from packet characteristics
            features = [
                packet_features.get('src_port', 0) or 0,  # Source port
                packet_features.get('dst_port', 0) or 0,  # Destination port
                packet_features.get('protocol', 0) or 0,  # Protocol number
                len(str(packet_features))  # Packet data length (simple feature)
            ]
            return features
        except:
            return None

    def generate_training_data(self):
        """Generate synthetic training data for model demonstration"""
        # Set random seed for reproducibility
        np.random.seed(42)
        n_samples = 1000  # Number of samples per class

        # Generate normal traffic features (lower values)
        normal_features = np.random.normal(50, 10, (n_samples, 4))
        normal_labels = np.zeros(n_samples)  # 0 = normal

        # Generate attack traffic features (higher values)
        attack_features = np.random.normal(150, 30, (n_samples, 4))
        attack_labels = np.ones(n_samples)  # 1 = attack

        # Combine normal and attack data
        features = np.vstack([normal_features, attack_features])
        labels = np.hstack([normal_labels, attack_labels])

        return features, labels
