import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

def generate_sample_data(num_users=10, days=7, anomaly_percentage=0.05):
    """
    Generate sample vault access data for demonstration purposes.
    
    Parameters:
    -----------
    num_users : int
        Number of users to generate data for
    days : int
        Number of days of data to generate
    anomaly_percentage : float
        Percentage of data that should be anomalous (0.0 to 1.0)
        
    Returns:
    --------
    pandas.DataFrame
        DataFrame containing generated access logs
    """
    # Constants for data generation
    actions = ['read', 'write', 'delete', 'update', 'download', 'upload', 'view']
    resources = ['financial_report.pdf', 'customer_data.csv', 'trade_secrets.doc', 
                'credentials.json', 'system_backup.zip', 'source_code.tar.gz',
                'encryption_keys.dat', 'user_database.sql', 'contracts.pdf',
                'strategic_plan.pptx']
    locations = ['New York', 'San Francisco', 'Chicago', 'Austin', 'Seattle', 
                'Boston', 'London', 'Paris', 'Tokyo', 'Sydney']
    device_types = ['desktop', 'laptop', 'mobile', 'tablet', 'server']
    
    # Create user profiles to simulate consistent behavior
    user_profiles = {}
    for i in range(num_users):
        user_id = f"user_{i+1:03d}"
        user_profiles[user_id] = {
            'typical_hours': np.random.normal(12, 3, 1)[0],  # Center of user's typical activity time
            'hour_variance': np.random.uniform(1, 3),  # How much the user's activity time varies
            'favorite_locations': random.sample(locations, min(3, len(locations))),  # User's common locations
            'primary_device': random.choice(device_types),  # User's primary device
            'secondary_device': random.choice([d for d in device_types if d != user_profiles.get(user_id, {}).get('primary_device')]),
            'common_resources': random.sample(resources, min(5, len(resources))),  # Resources commonly accessed
            'success_rate': np.random.uniform(0.95, 0.99)  # Normal success rate for the user
        }
    
    # Generate normal data
    normal_data = []
    
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    date_range = (end_date - start_date).days
    
    # Calculate total number of records to generate
    total_records = num_users * 10 * days  # Assuming avg 10 accesses per user per day
    normal_records = int(total_records * (1 - anomaly_percentage))
    anomaly_records = total_records - normal_records
    
    # Generate normal records
    for _ in range(normal_records):
        # Pick a random user and their profile
        user_id = random.choice(list(user_profiles.keys()))
        profile = user_profiles[user_id]
        
        # Generate timestamp based on user's typical pattern
        random_day = random.randint(0, date_range)
        random_date = start_date + timedelta(days=random_day)
        
        # Time of day follows user's typical hours
        hour = np.random.normal(profile['typical_hours'], profile['hour_variance'])
        hour = max(0, min(23, int(hour)))  # Constrain to valid hours
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        
        timestamp = random_date.replace(hour=hour, minute=minute, second=second)
        
        # Other fields based on user profile
        location = random.choice(profile['favorite_locations'])
        device_type = profile['primary_device'] if random.random() < 0.8 else profile['secondary_device']
        resource = random.choice(profile['common_resources'])
        action = random.choice(actions)
        success = random.random() < profile['success_rate']
        
        normal_data.append({
            'user_id': user_id,
            'timestamp': timestamp,
            'action': action,
            'resource': resource,
            'location': location,
            'device_type': device_type,
            'success': success
        })
    
    # Generate anomalous data
    anomaly_data = []
    
    for _ in range(anomaly_records):
        # Pick a random user and their profile
        user_id = random.choice(list(user_profiles.keys()))
        profile = user_profiles[user_id]
        
        # Generate timestamp based on unusual patterns
        random_day = random.randint(0, date_range)
        random_date = start_date + timedelta(days=random_day)
        
        # Anomaly type determines what kind of anomaly to generate
        anomaly_type = random.choice(['odd_hour', 'unusual_location', 'unusual_device', 'rare_resource', 'failed_access'])
        
        if anomaly_type == 'odd_hour':
            # Time far from user's typical hours (middle of night, etc.)
            offset = 12  # 12 hours from typical time
            if profile['typical_hours'] < 12:
                hour = int(profile['typical_hours'] + offset)
            else:
                hour = int(profile['typical_hours'] - offset)
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            
            location = random.choice(profile['favorite_locations'])
            device_type = profile['primary_device']
            resource = random.choice(profile['common_resources'])
            action = random.choice(actions)
            success = random.random() < profile['success_rate']
            
        elif anomaly_type == 'unusual_location':
            # Location the user doesn't normally access from
            hour = int(np.random.normal(profile['typical_hours'], profile['hour_variance']))
            hour = max(0, min(23, hour))
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            
            # Pick a location not in the user's favorites
            location = random.choice([loc for loc in locations if loc not in profile['favorite_locations']])
            device_type = profile['primary_device']
            resource = random.choice(profile['common_resources'])
            action = random.choice(actions)
            success = random.random() < profile['success_rate']
            
        elif anomaly_type == 'unusual_device':
            # Device the user doesn't normally use
            hour = int(np.random.normal(profile['typical_hours'], profile['hour_variance']))
            hour = max(0, min(23, hour))
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            
            location = random.choice(profile['favorite_locations'])
            # Pick a device that's not the user's primary or secondary
            device_type = random.choice([d for d in device_types if d != profile['primary_device'] and d != profile['secondary_device']])
            resource = random.choice(profile['common_resources'])
            action = random.choice(actions)
            success = random.random() < profile['success_rate']
            
        elif anomaly_type == 'rare_resource':
            # Access to a resource the user doesn't typically access
            hour = int(np.random.normal(profile['typical_hours'], profile['hour_variance']))
            hour = max(0, min(23, hour))
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            
            location = random.choice(profile['favorite_locations'])
            device_type = profile['primary_device']
            # Pick a resource not in the user's common resources
            resource = random.choice([res for res in resources if res not in profile['common_resources']])
            action = random.choice(actions)
            success = random.random() < profile['success_rate']
            
        elif anomaly_type == 'failed_access':
            # Multiple failed attempts
            hour = int(np.random.normal(profile['typical_hours'], profile['hour_variance']))
            hour = max(0, min(23, hour))
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            
            location = random.choice(profile['favorite_locations'])
            device_type = profile['primary_device']
            resource = random.choice(profile['common_resources'])
            action = random.choice(actions)
            success = False  # Forced failure
        
        timestamp = random_date.replace(hour=hour, minute=minute, second=second)
        
        anomaly_data.append({
            'user_id': user_id,
            'timestamp': timestamp,
            'action': action,
            'resource': resource,
            'location': location,
            'device_type': device_type,
            'success': success
        })
    
    # Combine normal and anomaly data
    all_data = normal_data + anomaly_data
    
    # Convert to DataFrame and sort by timestamp
    df = pd.DataFrame(all_data)
    df = df.sort_values('timestamp')
    
    # Format timestamp as string for better compatibility
    df['timestamp'] = df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
    
    return df
