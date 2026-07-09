import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler

def train_anomaly_detector(features_df, algorithm='Isolation Forest'):
    """
    Train an anomaly detection model.
    
    Parameters:
    -----------
    features_df : pandas.DataFrame
        DataFrame with engineered features
    algorithm : str
        The algorithm to use for anomaly detection
        Options: 'Isolation Forest', 'Local Outlier Factor', 'One-Class SVM'
        
    Returns:
    --------
    model : The trained anomaly detection model
    """
    # Standardize features
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(features_df)
    
    # Train model based on selected algorithm
    if algorithm == 'Isolation Forest':
        model = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination='auto',
            random_state=42
        )
        model.fit(scaled_features)
    
    elif algorithm == 'Local Outlier Factor':
        model = LocalOutlierFactor(
            n_neighbors=20,
            contamination='auto',
            novelty=True
        )
        model.fit(scaled_features)
    
    elif algorithm == 'One-Class SVM':
        model = OneClassSVM(
            kernel='rbf',
            gamma='scale',
            nu=0.05  # Approximate percentage of outliers
        )
        model.fit(scaled_features)
    
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")
    
    return model

def detect_anomalies(processed_df, features_df, model, threshold=0.9, algorithm='Isolation Forest'):
    """
    Detect anomalies in the data using the trained model.
    
    Parameters:
    -----------
    processed_df : pandas.DataFrame
        The original processed data with all columns
    features_df : pandas.DataFrame
        DataFrame with engineered features used for anomaly detection
    model : The trained anomaly detection model
    threshold : float
        Threshold value for determining anomalies (0.0 to 1.0)
        Higher values make the detector more sensitive to anomalies
    algorithm : str
        The algorithm used for anomaly detection
        
    Returns:
    --------
    pandas.DataFrame
        Original data with anomaly scores and flags
    """
    # Standardize features
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(features_df)
    
    # Get anomaly scores based on algorithm
    if algorithm == 'Isolation Forest':
        # For Isolation Forest, we use the decision function
        # More negative = more anomalous
        scores = -model.decision_function(scaled_features)
    
    elif algorithm == 'Local Outlier Factor':
        # For LOF, we use the decision function
        # More negative = more anomalous
        scores = -model.decision_function(scaled_features)
    
    elif algorithm == 'One-Class SVM':
        # For One-Class SVM, we use the decision function
        # More negative = more anomalous
        scores = -model.decision_function(scaled_features)
    
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")
    
    # Normalize scores to 0-1 range for easier interpretation
    min_score = np.min(scores)
    max_score = np.max(scores)
    normalized_scores = (scores - min_score) / (max_score - min_score) if max_score > min_score else scores
    
    # Create results DataFrame with original data
    results_df = processed_df.copy()
    
    # Add anomaly scores
    results_df['anomaly_score'] = normalized_scores
    
    # Add anomaly flag based on threshold
    # Higher threshold = more sensitive detection
    adjusted_threshold = 1 - threshold  # Invert threshold for intuitive usage
    percentile_threshold = np.percentile(normalized_scores, 100 * (1 - adjusted_threshold))
    results_df['is_anomaly'] = (normalized_scores >= percentile_threshold).astype(int)
    
    return results_df
