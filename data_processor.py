import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.preprocessing import LabelEncoder

def process_data(df):
    """
    Process raw access log data for analysis.
    
    Parameters:
    -----------
    df : pandas.DataFrame
        Raw access log data
        
    Returns:
    --------
    pandas.DataFrame
        Processed DataFrame with additional features
    """
    # Make a copy to avoid modifying the original
    processed_df = df.copy()
    
    # Convert timestamp to datetime if it's not already
    if not pd.api.types.is_datetime64_dtype(processed_df['timestamp']):
        processed_df['timestamp'] = pd.to_datetime(processed_df['timestamp'])
    
    # Extract time components
    processed_df['date'] = processed_df['timestamp'].dt.date
    processed_df['day_of_week'] = processed_df['timestamp'].dt.dayofweek
    processed_df['hour_of_day'] = processed_df['timestamp'].dt.hour
    processed_df['minute'] = processed_df['timestamp'].dt.minute
    processed_df['is_weekend'] = processed_df['day_of_week'].apply(lambda x: 1 if x >= 5 else 0)
    processed_df['is_business_hours'] = processed_df['hour_of_day'].apply(lambda x: 1 if 9 <= x <= 17 else 0)
    
    # Count previous access attempts per user
    processed_df = processed_df.sort_values('timestamp')
    processed_df['prev_access_count'] = processed_df.groupby('user_id').cumcount()
    
    # Calculate time since last access (for each user)
    processed_df['prev_timestamp'] = processed_df.groupby('user_id')['timestamp'].shift(1)
    processed_df['time_since_last_access'] = (processed_df['timestamp'] - processed_df['prev_timestamp']).dt.total_seconds() / 3600  # in hours
    
    # Fill NaN values for first access
    processed_df['time_since_last_access'] = processed_df['time_since_last_access'].fillna(24)  # Assume 24 hours for first access
    
    # Calculate success rate over time (rolling window)
    processed_df['success_int'] = processed_df['success'].astype(int)
    processed_df['success_rate'] = processed_df.groupby('user_id')['success_int'].transform(
        lambda x: x.rolling(window=5, min_periods=1).mean()
    )
    
    # Calculate frequency features
    processed_df['location_freq'] = processed_df.groupby(['user_id', 'location'])['timestamp'].transform('count') / \
                                   processed_df.groupby('user_id')['timestamp'].transform('count')
    
    processed_df['device_freq'] = processed_df.groupby(['user_id', 'device_type'])['timestamp'].transform('count') / \
                                 processed_df.groupby('user_id')['timestamp'].transform('count')
    
    processed_df['resource_freq'] = processed_df.groupby(['user_id', 'resource'])['timestamp'].transform('count') / \
                                   processed_df.groupby('user_id')['timestamp'].transform('count')
    
    processed_df['action_freq'] = processed_df.groupby(['user_id', 'action'])['timestamp'].transform('count') / \
                                 processed_df.groupby('user_id')['timestamp'].transform('count')
    
    # Calculate hour_of_day deviation from user's mean
    processed_df['user_mean_hour'] = processed_df.groupby('user_id')['hour_of_day'].transform('mean')
    processed_df['hour_deviation'] = abs(processed_df['hour_of_day'] - processed_df['user_mean_hour'])
    
    return processed_df

def engineer_features(processed_df):
    """
    Engineer features for anomaly detection model.
    
    Parameters:
    -----------
    processed_df : pandas.DataFrame
        Processed DataFrame with time and behavioral features
        
    Returns:
    --------
    pandas.DataFrame
        DataFrame with engineered features ready for modeling
    """
    # Select relevant columns for feature engineering
    feature_df = processed_df[['prev_access_count', 'time_since_last_access', 'hour_of_day', 
                              'is_weekend', 'is_business_hours', 'location_freq',
                              'device_freq', 'resource_freq', 'action_freq', 
                              'success_rate', 'hour_deviation']].copy()
    
    # Encode categorical variables if any left
    categorical_columns = feature_df.select_dtypes(include=['object', 'category']).columns
    for col in categorical_columns:
        le = LabelEncoder()
        feature_df[col] = le.fit_transform(feature_df[col])
    
    # Handle any missing values
    feature_df = feature_df.fillna(0)
    
    return feature_df
