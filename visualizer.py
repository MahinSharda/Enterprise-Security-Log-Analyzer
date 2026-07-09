import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

def plot_access_patterns(processed_df, anomalies_df):
    """
    Create a visualization of access patterns with anomalies highlighted.
    
    Parameters:
    -----------
    processed_df : pandas.DataFrame
        Processed access log data
    anomalies_df : pandas.DataFrame
        DataFrame with anomaly flags and scores
        
    Returns:
    --------
    plotly.graph_objects.Figure
        Figure with access patterns visualization
    """
    # Ensure timestamp is datetime
    if not pd.api.types.is_datetime64_dtype(processed_df['timestamp']):
        processed_df['timestamp'] = pd.to_datetime(processed_df['timestamp'])
    
    # Combine data with anomaly flags
    df_with_anomalies = processed_df.copy()
    df_with_anomalies['is_anomaly'] = anomalies_df['is_anomaly']
    df_with_anomalies['anomaly_score'] = anomalies_df['anomaly_score']
    
    # Create figure with subplots
    fig = make_subplots(
        rows=2, cols=1,
        row_heights=[0.7, 0.3],
        subplot_titles=("User Access Patterns", "Access Volume Over Time"),
        vertical_spacing=0.1
    )
    
    # Plot 1: User Access Patterns (scatter plot)
    # Color points by anomaly status
    normal_data = df_with_anomalies[df_with_anomalies['is_anomaly'] == 0]
    anomaly_data = df_with_anomalies[df_with_anomalies['is_anomaly'] == 1]
    
    # Add normal points
    fig.add_trace(
        go.Scatter(
            x=normal_data['timestamp'],
            y=normal_data['user_id'],
            mode='markers',
            marker=dict(
                color='blue',
                size=8,
                opacity=0.6
            ),
            name='Normal Access',
            hovertemplate=(
                '<b>User:</b> %{y}<br>' +
                '<b>Time:</b> %{x}<br>' +
                '<b>Action:</b> %{customdata[0]}<br>' +
                '<b>Resource:</b> %{customdata[1]}<br>' +
                '<b>Device:</b> %{customdata[2]}<br>' +
                '<b>Location:</b> %{customdata[3]}<br>'
            ),
            customdata=normal_data[['action', 'resource', 'device_type', 'location']]
        ),
        row=1, col=1
    )
    
    # Add anomaly points
    fig.add_trace(
        go.Scatter(
            x=anomaly_data['timestamp'],
            y=anomaly_data['user_id'],
            mode='markers',
            marker=dict(
                color='red',
                size=12,
                symbol='diamond',
                line=dict(color='black', width=1)
            ),
            name='Anomalous Access',
            hovertemplate=(
                '<b>User:</b> %{y}<br>' +
                '<b>Time:</b> %{x}<br>' +
                '<b>Action:</b> %{customdata[0]}<br>' +
                '<b>Resource:</b> %{customdata[1]}<br>' +
                '<b>Device:</b> %{customdata[2]}<br>' +
                '<b>Location:</b> %{customdata[3]}<br>' +
                '<b>Anomaly Score:</b> %{customdata[4]:.4f}<br>'
            ),
            customdata=anomaly_data[['action', 'resource', 'device_type', 'location', 'anomaly_score']]
        ),
        row=1, col=1
    )
    
    # Plot 2: Access volume over time (histogram)
    # Group by day and count
    df_with_anomalies['date'] = df_with_anomalies['timestamp'].dt.date
    access_by_date = df_with_anomalies.groupby('date')['user_id'].count().reset_index()
    access_by_date.columns = ['date', 'count']
    
    # Add histogram of access counts
    fig.add_trace(
        go.Bar(
            x=access_by_date['date'],
            y=access_by_date['count'],
            marker_color='lightblue',
            name='Access Volume'
        ),
        row=2, col=1
    )
    
    # Update layout
    fig.update_layout(
        height=800,
        title_text="Vault Access Patterns with Anomaly Detection",
        hovermode="closest",
        showlegend=True,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        )
    )
    
    fig.update_xaxes(title_text="Date/Time", row=1, col=1)
    fig.update_yaxes(title_text="User ID", row=1, col=1)
    fig.update_xaxes(title_text="Date", row=2, col=1)
    fig.update_yaxes(title_text="Access Count", row=2, col=1)
    
    return fig

def plot_anomalies_timeline(anomalies_df):
    """
    Create a timeline visualization of anomalies.
    
    Parameters:
    -----------
    anomalies_df : pandas.DataFrame
        DataFrame with anomaly flags and scores
        
    Returns:
    --------
    plotly.graph_objects.Figure
        Figure with anomalies timeline visualization
    """
    # Ensure timestamp is datetime
    if not pd.api.types.is_datetime64_dtype(anomalies_df['timestamp']):
        anomalies_df['timestamp'] = pd.to_datetime(anomalies_df['timestamp'])
    
    # Extract only anomalies
    anomalies_only = anomalies_df[anomalies_df['is_anomaly'] == 1].copy()
    
    if len(anomalies_only) == 0:
        # If no anomalies found, create an empty figure with a message
        fig = go.Figure()
        fig.add_annotation(
            text="No anomalies detected with current sensitivity settings",
            xref="paper", yref="paper",
            x=0.5, y=0.5,
            showarrow=False,
            font=dict(size=20)
        )
        return fig
    
    # Sort by timestamp
    anomalies_only = anomalies_only.sort_values('timestamp')
    
    # Create figure
    fig = go.Figure()
    
    # Add scatter plot for anomalies
    fig.add_trace(
        go.Scatter(
            x=anomalies_only['timestamp'],
            y=anomalies_only['anomaly_score'],
            mode='markers+lines',
            marker=dict(
                color=anomalies_only['anomaly_score'],
                colorscale='Reds',
                size=12,
                showscale=True,
                colorbar=dict(
                    title="Anomaly Score",
                    tickmode="auto",
                    ticks="outside"
                )
            ),
            line=dict(color='rgba(255,0,0,0.2)', dash='dot'),
            name='Anomaly Score',
            hovertemplate=(
                '<b>Time:</b> %{x}<br>' +
                '<b>Anomaly Score:</b> %{y:.4f}<br>' +
                '<b>User:</b> %{customdata[0]}<br>' +
                '<b>Action:</b> %{customdata[1]}<br>' +
                '<b>Resource:</b> %{customdata[2]}<br>' +
                '<b>Location:</b> %{customdata[3]}<br>' +
                '<b>Device:</b> %{customdata[4]}<br>'
            ),
            customdata=anomalies_only[['user_id', 'action', 'resource', 'location', 'device_type']]
        )
    )
    
    # Update layout
    fig.update_layout(
        title="Anomalies Timeline",
        xaxis_title="Date/Time",
        yaxis_title="Anomaly Score",
        height=500,
        hovermode="closest"
    )
    
    return fig

def plot_feature_importance(model, features_df):
    """
    Create a visualization of feature importance.
    
    Parameters:
    -----------
    model : trained model
        The trained anomaly detection model (must have feature_importances_ attribute)
    features_df : pandas.DataFrame
        DataFrame with features used for training
        
    Returns:
    --------
    plotly.graph_objects.Figure
        Figure with feature importance visualization
    """
    # Check if model has feature_importances_ attribute
    if not hasattr(model, 'feature_importances_'):
        raise ValueError("Model does not have feature_importances_ attribute")
    
    # Get feature names and importance scores
    feature_names = features_df.columns
    importances = model.feature_importances_
    
    # Sort by importance
    indices = np.argsort(importances)
    sorted_names = [feature_names[i] for i in indices]
    sorted_importances = importances[indices]
    
    # Create horizontal bar chart
    fig = go.Figure()
    fig.add_trace(
        go.Bar(
            y=sorted_names,
            x=sorted_importances,
            orientation='h',
            marker=dict(
                color=sorted_importances,
                colorscale='Viridis'
            )
        )
    )
    
    fig.update_layout(
        title="Feature Importance for Anomaly Detection",
        xaxis_title="Importance Score",
        yaxis_title="Feature",
        height=500
    )
    
    return fig

def plot_confusion_matrix(y_true, y_pred):
    """
    Create a confusion matrix visualization.
    
    Parameters:
    -----------
    y_true : array-like
        True labels
    y_pred : array-like
        Predicted labels
        
    Returns:
    --------
    plotly.graph_objects.Figure
        Figure with confusion matrix visualization
    """
    from sklearn.metrics import confusion_matrix
    
    # Compute confusion matrix
    cm = confusion_matrix(y_true, y_pred)
    
    # Convert to percentage
    cm_percent = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis] * 100
    
    # Labels for matrix
    labels = ['Normal', 'Anomaly']
    
    # Create annotation text
    annotations = []
    for i in range(len(cm)):
        for j in range(len(cm[i])):
            annotations.append(
                dict(
                    x=labels[j],
                    y=labels[i],
                    text=f"{cm[i, j]}<br>({cm_percent[i, j]:.1f}%)",
                    showarrow=False,
                    font=dict(size=14, color="white" if cm[i, j] > cm.max()/2 else "black")
                )
            )
    
    # Create heatmap
    fig = go.Figure(data=go.Heatmap(
        z=cm,
        x=labels,
        y=labels,
        colorscale='Blues',
        showscale=False
    ))
    
    # Add annotations
    fig.update_layout(
        title="Confusion Matrix",
        annotations=annotations,
        xaxis=dict(title="Predicted"),
        yaxis=dict(title="Actual", autorange="reversed")
    )
    
    return fig
