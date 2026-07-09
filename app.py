import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import os
import io
import logging

from alert_mailer import send_security_alert
logging.basicConfig(
    filename='security_alerts.log',
    level=logging.WARNING,
    format='%(asctime)s - ALERT: %(message)s'
)

from data_generator import generate_sample_data
from data_processor import process_data, engineer_features
from anomaly_detector import train_anomaly_detector, detect_anomalies
from visualizer import (
    plot_access_patterns, 
    plot_anomalies_timeline, 
    plot_feature_importance,
    plot_confusion_matrix
)
from utils import save_to_csv
from ai_analyst import generate_threat_analysis

# Set page configuration
st.set_page_config(
    page_title="Enterprise Security Log Analyzer",
    page_icon="🔒",
    layout="wide"
)

# Initialize session state variables if they don't exist
if 'data' not in st.session_state:
    st.session_state.data = None
if 'processed_data' not in st.session_state:
    st.session_state.processed_data = None
if 'model' not in st.session_state:
    st.session_state.model = None
if 'anomalies' not in st.session_state:
    st.session_state.anomalies = None
if 'threshold' not in st.session_state:
    st.session_state.threshold = 0.9  # Default threshold value

# Main app title
st.title("Enterprise Security Log Analyzer")

# Sidebar for controls
with st.sidebar:
    st.header("Controls")
    
    # Data options
    st.subheader("Data Source")
    data_source = st.radio(
        "Select data source:",
        ["Upload your access logs", "Generate sample data for demonstration"]
    )
    
    if data_source == "Upload your access logs":
        uploaded_file = st.file_uploader("Upload your access logs (CSV)", type=["csv"])
        if uploaded_file is not None:
            try:
                data = pd.read_csv(uploaded_file)
                st.session_state.data = data
                st.success("Data uploaded successfully!")
            except Exception as e:
                st.error(f"Error loading data: {e}")
                st.info("Please make sure your CSV has the required columns: user_id, timestamp, action, resource, location, device_type, success")
    else:
        st.info("Sample data will be generated for demonstration purposes")
        num_users = st.slider("Number of users", 5, 50, 10)
        days_of_data = st.slider("Days of data", 1, 30, 7)
        anomaly_percentage = st.slider("Anomaly percentage", 1, 20, 5)
        
        if st.button("Generate Sample Data"):
            with st.spinner("Generating sample data..."):
                st.session_state.data = generate_sample_data(
                    num_users=num_users,
                    days=days_of_data,
                    anomaly_percentage=anomaly_percentage/100
                )
                st.success(f"Generated {len(st.session_state.data)} access records")
    
    # Model parameters
    st.subheader("Anomaly Detection Settings")
    algorithm = st.selectbox(
        "Select anomaly detection algorithm",
        ["Isolation Forest", "Local Outlier Factor", "One-Class SVM"]
    )
    
    # Sensitivity slider - this controls the threshold for anomaly detection
    sensitivity = st.slider(
        "Detection Sensitivity", 
        0.0, 1.0, st.session_state.threshold, 0.05,
        help="Higher values make the detector more sensitive to anomalies"
    )
    st.session_state.threshold = sensitivity
    
    # Add train button
    train_button = st.button("Train Detector")
    
    # Export options
    st.subheader("Export Options")
    if st.session_state.anomalies is not None:
        if st.button("Export Anomalies to CSV"):
            csv_data = save_to_csv(st.session_state.anomalies)
            st.download_button(
                label="Download CSV",
                data=csv_data,
                file_name=f"vault_anomalies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )

# Main content area
if st.session_state.data is not None:
    # Display raw data
    st.header("Access Log Data")
    st.write("Sample of raw access logs:")
    st.dataframe(st.session_state.data.head(10))
    
    # Process data when the train button is clicked
    if train_button:
        with st.spinner("Processing data and training model..."):
            # Process data
            st.session_state.processed_data = process_data(st.session_state.data)
            
            # Engineer features
            features_df = engineer_features(st.session_state.processed_data)
            
            # Train model based on selected algorithm
            st.session_state.model = train_anomaly_detector(
                features_df, 
                algorithm=algorithm
            )
            
            # Detect anomalies
            st.session_state.anomalies = detect_anomalies(
                st.session_state.processed_data,
                features_df,
                st.session_state.model,
                threshold=st.session_state.threshold,
                algorithm=algorithm
            )
            
            st.success("Model trained and anomalies detected!")
            
            anomaly_count = st.session_state.anomalies['is_anomaly'].sum()

            if anomaly_count > 0:
                st.toast(f"⚠️ HIGH ALERT: {anomaly_count} suspicious access events detected!", icon="🚨")

                suspicious_events = st.session_state.anomalies[st.session_state.anomalies['is_anomaly'] == 1]
                for _, row in suspicious_events.head(5).iterrows(): 
                    log_msg = f"Suspicious Activity - User: {row['user_id']}, Action: {row['action']}, Resource: {row['resource']}"
                    logging.warning(log_msg)

                first_anomaly = suspicious_events.iloc[0]
                send_security_alert(
                    user_id=first_anomaly['user_id'],
                    action=first_anomaly['action'],
                    resource=first_anomaly['resource'],
                    location=first_anomaly['location'],
                    time_str=str(first_anomaly['timestamp'])
                )
                st.info("📧 Automated Security Email Alert dispatched to admin.")    
    
    # If model is trained and anomalies are detected
    if st.session_state.anomalies is not None:
        st.header("Anomaly Detection Results")
        
        # Create tabs for different visualizations
        tab1, tab2, tab3, tab4 = st.tabs([
            "Access Patterns", 
            "Anomalies Timeline", 
            "Feature Analysis",
            "Anomaly Report"
        ])
        
        # Tab 1: Access Patterns
        with tab1:
            st.subheader("Vault Access Patterns")
            access_pattern_fig = plot_access_patterns(st.session_state.processed_data, st.session_state.anomalies)
            st.plotly_chart(access_pattern_fig, use_container_width=True)
            # --- NAYA AI SECTION YAHAN SE SHURU ---
            st.markdown("---")
            st.subheader("🤖 Deep AI Threat Analysis")
            st.write("Select a suspicious event from the data above to generate an instant AI security report.")
            
            # Sirf anomalies ko filter kar rahe hain AI analysis ke liye
            anomalies_only = st.session_state.anomalies[st.session_state.anomalies['is_anomaly'] == 1]
            
            if len(anomalies_only) > 0:
                # Ek unique dropdown specifically Tab 1 ke liye
                selected_idx_tab1 = st.selectbox(
                    "Select an event to investigate:",
                    range(len(anomalies_only)),
                    format_func=lambda i: f"{anomalies_only.iloc[i]['timestamp']} - User: {anomalies_only.iloc[i]['user_id']}",
                    key="tab1_ai_dropdown"
                )
                
                selected_event_tab1 = anomalies_only.iloc[selected_idx_tab1]
                
                # Seedha Button! Ab redirect hone par bhi user Tab 1 par hi rahega.
                if st.button("Generate AI Security Report", key="tab1_ai_button"):
                    with st.spinner("Gemini is analyzing the threat landscape..."):
                        ai_summary = generate_threat_analysis(
                            user_id=selected_event_tab1['user_id'],
                            action=selected_event_tab1['action'],
                            resource=selected_event_tab1['resource'],
                            location=selected_event_tab1['location'],
                            time=str(selected_event_tab1['timestamp'])
                        )
                        st.success(ai_summary)
            else:
                st.info("No anomalies detected yet. Adjust sensitivity and train the detector.")
            # --- NAYA AI SECTION YAHAN KHATAM ---
        # Tab 2: Anomalies Timeline
        with tab2:
            st.subheader("Anomalies Timeline")
            timeline_fig = plot_anomalies_timeline(st.session_state.anomalies)
            st.plotly_chart(timeline_fig, use_container_width=True)
            
            # Show statistics
            anomaly_count = st.session_state.anomalies['is_anomaly'].sum()
            total_count = len(st.session_state.anomalies)
            anomaly_percentage = (anomaly_count / total_count) * 100
            
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Access Events", total_count)
            col2.metric("Anomalous Events", anomaly_count)
            col3.metric("Anomaly Percentage", f"{anomaly_percentage:.2f}%")
        
        # Tab 3: Feature Analysis
        with tab3:
            st.subheader("Feature Importance and Analysis")
            
            # Only show feature importance for Isolation Forest as other algorithms don't provide this
            if algorithm == "Isolation Forest" and hasattr(st.session_state.model, 'feature_importances_'):
                feature_fig = plot_feature_importance(st.session_state.model, 
                                                    engineer_features(st.session_state.processed_data))
                st.plotly_chart(feature_fig, use_container_width=True)
            else:
                st.info("Feature importance is only available for Isolation Forest algorithm.")
            
            # Add other feature visualizations
            st.subheader("Feature Distributions")
            features_df = engineer_features(st.session_state.processed_data)
            
            # Add anomaly flag to features for coloring
            features_df_with_anomaly = features_df.copy()
            features_df_with_anomaly['is_anomaly'] = st.session_state.anomalies['is_anomaly']
            
            # Select a feature to visualize
            feature_to_viz = st.selectbox(
                "Select feature to visualize", 
                features_df.columns.tolist()
            )
            
            # Create histogram with two traces
            fig = go.Figure()
            
            # Normal events
            normal_data = features_df_with_anomaly[features_df_with_anomaly['is_anomaly'] == 0][feature_to_viz]
            fig.add_trace(go.Histogram(
                x=normal_data,
                name='Normal Events',
                marker_color='blue',
                opacity=0.6
            ))
            
            # Anomalous events
            anomaly_data = features_df_with_anomaly[features_df_with_anomaly['is_anomaly'] == 1][feature_to_viz]
            fig.add_trace(go.Histogram(
                x=anomaly_data,
                name='Anomalous Events',
                marker_color='red',
                opacity=0.6
            ))
            
            fig.update_layout(
                title=f'Distribution of {feature_to_viz}',
                xaxis_title=feature_to_viz,
                yaxis_title='Count',
                barmode='overlay'
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        # Tab 4: Anomaly Report
        with tab4:
            st.subheader("Detailed Anomaly Report")
            
            # Filter to show only anomalies or all data
            show_only_anomalies = st.checkbox("Show only anomalies", value=True)
            
            if show_only_anomalies:
                filtered_anomalies = st.session_state.anomalies[st.session_state.anomalies['is_anomaly'] == 1]
            else:
                filtered_anomalies = st.session_state.anomalies
            
            if len(filtered_anomalies) > 0:
                st.dataframe(filtered_anomalies.sort_values('timestamp', ascending=False))
                
                # Show details for selected anomaly
                st.subheader("Anomaly Investigation")
                
                selected_anomaly_idx = st.selectbox(
                    "Select an event to investigate:",
                    range(len(filtered_anomalies)),
                    format_func=lambda i: f"{filtered_anomalies.iloc[i]['timestamp']} - User: {filtered_anomalies.iloc[i]['user_id']}"
                )
                
                selected_anomaly = filtered_anomalies.iloc[selected_anomaly_idx]
                
                # Show details in columns
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("Event Details:")
                    details = {
                        "Timestamp": selected_anomaly['timestamp'],
                        "User ID": selected_anomaly['user_id'],
                        "Action": selected_anomaly['action'],
                        "Resource": selected_anomaly['resource'],
                        "Location": selected_anomaly['location'],
                        "Device Type": selected_anomaly['device_type'],
                        "Success": "Yes" if selected_anomaly['success'] else "No",
                        "Anomaly Score": f"{selected_anomaly['anomaly_score']:.4f}"
                    }
                    
                    for key, value in details.items():
                        st.text(f"{key}: {value}")
                
                with col2:
                    st.write("Why might this be an anomaly?")
                    
                    # Get user's typical behavior
                    user_data = st.session_state.processed_data[
                        st.session_state.processed_data['user_id'] == selected_anomaly['user_id']
                    ]
                    
                    if len(user_data) > 1:  # If we have enough data for this user
                        typical_time = user_data['hour_of_day'].median()
                        typical_locations = user_data['location'].value_counts().index.tolist()
                        typical_devices = user_data['device_type'].value_counts().index.tolist()
                        
                        anomaly_reasons = []
                        
                        # Check time
                        if abs(selected_anomaly['hour_of_day'] - typical_time) > 6:  # More than 6 hours from typical time
                            anomaly_reasons.append(f"Unusual access time: {selected_anomaly['hour_of_day']} (typical: {typical_time:.1f})")
                        
                        # Check location
                        if selected_anomaly['location'] not in typical_locations[:1]:  # Not in top locations
                            anomaly_reasons.append(f"Unusual location: {selected_anomaly['location']} (typical: {typical_locations[0] if typical_locations else 'N/A'})")
                        
                        # Check device
                        if selected_anomaly['device_type'] not in typical_devices[:1]:  # Not in top devices
                            anomaly_reasons.append(f"Unusual device: {selected_anomaly['device_type']} (typical: {typical_devices[0] if typical_devices else 'N/A'})")
                        
                        # Check failed attempts
                        if not selected_anomaly['success']:
                            anomaly_reasons.append("Failed access attempt")
                        
                        # Display reasons
                        if anomaly_reasons:
                            for reason in anomaly_reasons:
                                st.warning(reason)
                        else:
                            st.info("Complex pattern detected by the model, but no simple explanation available.")
                    else:
                        st.info("Not enough data for this user to establish typical patterns.")

            else:
                st.info("No anomalies detected with current settings.")

else:
    # Show welcome message and instructions when no data is loaded
    st.info("Welcome to the Enterprise Security Log Analyzer. To get started, please upload your access log data or generate sample data using the sidebar controls.")
    
    # Display explanation of the application
    st.header("About this Application")
    st.write("""
    The Enterprise Security Log Analyzer helps security teams identify suspicious access patterns to secure vaults or encrypted storage systems. 
    
    **Features:**
    - Developed for automated industrial security monitoring
    - Analyze user access patterns over time
    - Detect unusual behavior using machine learning
    - Visualize normal vs. anomalous activities
    - Configure detection sensitivity
    - Export reports for further investigation
    
    **How it works:**
    1. Load your access log data (or generate sample data)
    2. Configure anomaly detection parameters
    3. Train the detector
    4. Review identified anomalies and visualizations
    5. Export findings for investigation
    
    **Required data format:**
    Your data should contain information about access events, including user ID, timestamp, action type, resource, location, device type, and success status.
    """)
    
    # Display sample data format
    st.subheader("Expected Data Format")
    sample_format = pd.DataFrame({
        'user_id': ['user123', 'user456'],
        'timestamp': ['2023-01-01 08:30:45', '2023-01-01 14:20:30'],
        'action': ['read', 'write'],
        'resource': ['document.pdf', 'config.json'],
        'location': ['New York', 'San Francisco'],
        'device_type': ['desktop', 'mobile'],
        'success': [True, False]
    })
    
    st.dataframe(sample_format)
