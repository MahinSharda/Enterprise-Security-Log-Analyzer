import pandas as pd
import io
from datetime import datetime

def save_to_csv(df):
    """
    Convert a DataFrame to CSV format for download.
    
    Parameters:
    -----------
    df : pandas.DataFrame
        DataFrame to convert to CSV
        
    Returns:
    --------
    str
        CSV data as a string
    """
    # Filter to only anomalies if needed
    if 'is_anomaly' in df.columns:
        export_df = df[df['is_anomaly'] == 1].copy()
    else:
        export_df = df.copy()
    
    # Sort by timestamp for better readability
    if 'timestamp' in export_df.columns:
        export_df = export_df.sort_values('timestamp', ascending=False)
    
    # Select relevant columns for report
    if 'is_anomaly' in export_df.columns and 'anomaly_score' in export_df.columns:
        # Keep all relevant info for anomaly report
        columns_to_keep = [
            'timestamp', 'user_id', 'action', 'resource', 
            'location', 'device_type', 'success', 'anomaly_score'
        ]
        export_df = export_df[[col for col in columns_to_keep if col in export_df.columns]]
    
    # Convert to CSV
    csv_buffer = io.StringIO()
    export_df.to_csv(csv_buffer, index=False)
    csv_string = csv_buffer.getvalue()
    
    return csv_string

def format_timestamp(timestamp_str):
    """
    Format a timestamp string into a readable format.
    
    Parameters:
    -----------
    timestamp_str : str
        Timestamp string to format
        
    Returns:
    --------
    str
        Formatted timestamp string
    """
    try:
        dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        return dt.strftime('%b %d, %Y %I:%M %p')
    except:
        return timestamp_str
