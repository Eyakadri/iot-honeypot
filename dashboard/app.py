#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dashboard application for the Advanced IoT Honeypot.
Implements a Flask/Dash web interface for visualizing honeypot data.
"""

import os
import json
import time
import datetime
from typing import Dict, Any, List, Optional

import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import flask

from logger import get_logger
from config import get_config
from database import get_database

# Initialize logger
logger = get_logger("dashboard")

# Initialize database
db = get_database()

# Initialize Flask server
server = flask.Flask(__name__)

# Initialize Dash app
app = dash.Dash(
    __name__,
    server=server,
    external_stylesheets=[
        "https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap",
    ],
    meta_tags=[
        {"name": "viewport", "content": "width=device-width, initial-scale=1.0"}
    ],
)

# App title
app.title = "IoT Honeypot Dashboard"

# Define colors
colors = {
    "background": "#1E1E1E",
    "text": "#FFFFFF",
    "primary": "#007BFF",
    "secondary": "#6C757D",
    "success": "#28A745",
    "danger": "#DC3545",
    "warning": "#FFC107",
    "info": "#17A2B8",
    "light": "#F8F9FA",
    "dark": "#343A40",
    "telnet": "#FF6B6B",
    "http": "#4ECDC4",
    "ssh": "#FFD166",
    "mqtt": "#06D6A0",
    "ftp": "#118AB2",
}

# Define app layout
app.layout = html.Div(
    style={
        "backgroundColor": colors["background"],
        "color": colors["text"],
        "fontFamily": "Roboto, sans-serif",
        "padding": "20px",
    },
    children=[
        # Header
        html.Div(
            style={
                "display": "flex",
                "justifyContent": "space-between",
                "alignItems": "center",
                "marginBottom": "20px",
            },
            children=[
                html.H1(
                    "Advanced IoT Honeypot Dashboard",
                    style={
                        "color": colors["primary"],
                        "marginBottom": "0",
                    },
                ),
                html.Div(
                    style={
                        "display": "flex",
                        "alignItems": "center",
                    },
                    children=[
                        html.Div(id="last-update", style={"marginRight": "20px"}),
                        dcc.Interval(
                            id="interval-component",
                            interval=10 * 1000,  # 10 seconds
                            n_intervals=0,
                        ),
                    ],
                ),
            ],
        ),
        
        # Stats cards
        html.Div(
            style={
                "display": "grid",
                "gridTemplateColumns": "repeat(auto-fit, minmax(200px, 1fr))",
                "gap": "20px",
                "marginBottom": "20px",
            },
            children=[
                # Connections card
                html.Div(
                    style={
                        "backgroundColor": colors["dark"],
                        "padding": "20px",
                        "borderRadius": "5px",
                        "boxShadow": "0 4px 6px rgba(0, 0, 0, 0.1)",
                    },
                    children=[
                        html.H3("Connections", style={"marginTop": "0"}),
                        html.Div(id="connections-count", style={"fontSize": "2rem"}),
                    ],
                ),
                
                # Auth attempts card
                html.Div(
                    style={
                        "backgroundColor": colors["dark"],
                        "padding": "20px",
                        "borderRadius": "5px",
                        "boxShadow": "0 4px 6px rgba(0, 0, 0, 0.1)",
                    },
                    children=[
                        html.H3("Auth Attempts", style={"marginTop": "0"}),
                        html.Div(id="auth-count", style={"fontSize": "2rem"}),
                    ],
                ),
                
                # Commands card
                html.Div(
                    style={
                        "backgroundColor": colors["dark"],
                        "padding": "20px",
                        "borderRadius": "5px",
                        "boxShadow": "0 4px 6px rgba(0, 0, 0, 0.1)",
                    },
                    children=[
                        html.H3("Commands", style={"marginTop": "0"}),
                        html.Div(id="commands-count", style={"fontSize": "2rem"}),
                    ],
                ),
                
                # HTTP requests card
                html.Div(
                    style={
                        "backgroundColor": colors["dark"],
                        "padding": "20px",
                        "borderRadius": "5px",
                        "boxShadow": "0 4px 6px rgba(0, 0, 0, 0.1)",
                    },
                    children=[
                        html.H3("HTTP Requests", style={"marginTop": "0"}),
                        html.Div(id="http-count", style={"fontSize": "2rem"}),
                    ],
                ),
                
                # Vulnerabilities card
                html.Div(
                    style={
                        "backgroundColor": colors["dark"],
                        "padding": "20px",
                        "borderRadius": "5px",
                        "boxShadow": "0 4px 6px rgba(0, 0, 0, 0.1)",
                    },
                    children=[
                        html.H3("Vulnerabilities", style={"marginTop": "0"}),
                        html.Div(id="vulnerabilities-count", style={"fontSize": "2rem"}),
                    ],
                ),
                
                # Malware card
                html.Div(
                    style={
                        "backgroundColor": colors["dark"],
                        "padding": "20px",
                        "borderRadius": "5px",
                        "boxShadow": "0 4px 6px rgba(0, 0, 0, 0.1)",
                    },
                    children=[
                        html.H3("Malware", style={"marginTop": "0"}),
                        html.Div(id="malware-count", style={"fontSize": "2rem"}),
                    ],
                ),
            ],
        ),
        
        # Charts row 1
        html.Div(
            style={
                "display": "grid",
                "gridTemplateColumns": "repeat(auto-fit, minmax(500px, 1fr))",
                "gap": "20px",
                "marginBottom": "20px",
            },
            children=[
                # Protocol distribution chart
                html.Div(
                    style={
                        "backgroundColor": colors["dark"],
                        "padding": "20px",
                        "borderRadius": "5px",
                        "boxShadow": "0 4px 6px rgba(0, 0, 0, 0.1)",
                    },
                    children=[
                        html.H3("Protocol Distribution", style={"marginTop": "0"}),
                        dcc.Graph(id="protocol-chart"),
                    ],
                ),
                
                # Country distribution chart
                html.Div(
                    style={
                        "backgroundColor": colors["dark"],
                        "padding": "20px",
                        "borderRadius": "5px",
                        "boxShadow": "0 4px 6px rgba(0, 0, 0, 0.1)",
                    },
                    children=[
                        html.H3("Country Distribution", style={"marginTop": "0"}),
                        dcc.Graph(id="country-chart"),
                    ],
                ),
            ],
        ),
        
        # Charts row 2
        html.Div(
            style={
                "display": "grid",
                "gridTemplateColumns": "repeat(auto-fit, minmax(500px, 1fr))",
                "gap": "20px",
                "marginBottom": "20px",
            },
            children=[
                # Attack map
                html.Div(
                    style={
                        "backgroundColor": colors["dark"],
                        "padding": "20px",
                        "borderRadius": "5px",
                        "boxShadow": "0 4px 6px rgba(0, 0, 0, 0.1)",
                    },
                    children=[
                        html.H3("Attack Map", style={"marginTop": "0"}),
                        dcc.Graph(id="attack-map"),
                    ],
                ),
                
                # Timeline chart
                html.Div(
                    style={
                        "backgroundColor": colors["dark"],
                        "padding": "20px",
                        "borderRadius": "5px",
                        "boxShadow": "0 4px 6px rgba(0, 0, 0, 0.1)",
                    },
                    children=[
                        html.H3("Attack Timeline", style={"marginTop": "0"}),
                        dcc.Graph(id="timeline-chart"),
                    ],
                ),
            ],
        ),
        
        # Tables row
        html.Div(
            style={
                "display": "grid",
                "gridTemplateColumns": "repeat(auto-fit, minmax(500px, 1fr))",
                "gap": "20px",
                "marginBottom": "20px",
            },
            children=[
                # Recent connections table
                html.Div(
                    style={
                        "backgroundColor": colors["dark"],
                        "padding": "20px",
                        "borderRadius": "5px",
                        "boxShadow": "0 4px 6px rgba(0, 0, 0, 0.1)",
                    },
                    children=[
                        html.H3("Recent Connections", style={"marginTop": "0"}),
                        dash_table.DataTable(
                            id="connections-table",
                            style_header={
                                "backgroundColor": colors["primary"],
                                "color": colors["text"],
                                "fontWeight": "bold",
                            },
                            style_cell={
                                "backgroundColor": colors["dark"],
                                "color": colors["text"],
                                "textAlign": "left",
                                "padding": "10px",
                            },
                            style_data_conditional=[
                                {
                                    "if": {"row_index": "odd"},
                                    "backgroundColor": "#2A2A2A",
                                }
                            ],
                            page_size=5,
                        ),
                    ],
                ),
                
                # Recent auth attempts table
                html.Div(
                    style={
                        "backgroundColor": colors["dark"],
                        "padding": "20px",
                        "borderRadius": "5px",
                        "boxShadow": "0 4px 6px rgba(0, 0, 0, 0.1)",
                    },
                    children=[
                        html.H3("Recent Auth Attempts", style={"marginTop": "0"}),
                        dash_table.DataTable(
                            id="auth-table",
                            style_header={
                                "backgroundColor": colors["primary"],
                                "color": colors["text"],
                                "fontWeight": "bold",
                            },
                            style_cell={
                                "backgroundColor": colors["dark"],
                                "color": colors["text"],
                                "textAlign": "left",
                                "padding": "10px",
                            },
                            style_data_conditional=[
                                {
                                    "if": {"row_index": "odd"},
                                    "backgroundColor": "#2A2A2A",
                                },
                                {
                                    "if": {
                                        "filter_query": "{success} eq true",
                                        "column_id": "success",
                                    },
                                    "backgroundColor": colors["success"],
                                    "color": colors["text"],
                                },
                                {
                                    "if": {
                                        "filter_query": "{success} eq false",
                                        "column_id": "success",
                                    },
                                    "backgroundColor": colors["danger"],
                                    "color": colors["text"],
                                },
                            ],
                            page_size=5,
                        ),
                    ],
                ),
            ],
        ),
        
        # Footer
        html.Div(
            style={
                "textAlign": "center",
                "marginTop": "40px",
                "color": colors["secondary"],
            },
            children=[
                html.P("Advanced IoT Honeypot - Final Year Project"),
                html.P("© 2025 Cybersecurity Research"),
            ],
        ),
    ],
)

# Callback for updating stats
@app.callback(
    [
        Output("last-update", "children"),
        Output("connections-count", "children"),
        Output("auth-count", "children"),
        Output("commands-count", "children"),
        Output("http-count", "children"),
        Output("vulnerabilities-count", "children"),
        Output("malware-count", "children"),
        Output("protocol-chart", "figure"),
        Output("country-chart", "figure"),
        Output("attack-map", "figure"),
        Output("timeline-chart", "figure"),
        Output("connections-table", "data"),
        Output("connections-table", "columns"),
        Output("auth-table", "data"),
        Output("auth-table", "columns"),
    ],
    [Input("interval-component", "n_intervals")]
)
def update_dashboard(n_intervals):
    """
    Update dashboard with latest data.
    
    Args:
        n_intervals: Number of intervals
        
    Returns:
        Updated dashboard components
    """
    # Get current time
    now = datetime.datetime.now()
    last_update = f"Last updated: {now.strftime('%Y-%m-%d %H:%M:%S')}"
    
    # Get stats
    stats = db.get_stats()
    
    # Set default values if stats are empty
    connections_count = stats.get("connections", 0)
    auth_count = stats.get("auth_attempts", 0)
    commands_count = stats.get("commands", 0)
    http_count = stats.get("http_requests", 0)
    vulnerabilities_count = stats.get("vulnerabilities", 0)
    malware_count = stats.get("malware", 0)
    
    # Protocol distribution chart
    protocol_data = stats.get("protocols", {})
    if not protocol_data:
        # Sample data for demonstration
        protocol_data = {
            "telnet": 45,
            "http": 30,
            "ssh": 15,
            "mqtt": 7,
            "ftp": 3,
        }
    
    protocol_df = pd.DataFrame({
        "Protocol": list(protocol_data.keys()),
        "Count": list(protocol_data.values())
    })
    
    protocol_colors = [
        colors.get(protocol.lower(), colors["primary"])
        for protocol in protocol_df["Protocol"]
    ]
    
    protocol_chart = px.pie(
        protocol_df,
        values="Count",
        names="Protocol",
        color="Protocol",
        color_discrete_map={
            protocol: color
            for protocol, color in zip(protocol_df["Protocol"], protocol_colors)
        },
        hole=0.4,
    )
    
    protocol_chart.update_layout(
        plot_bgcolor=colors["background"],
        paper_bgcolor=colors["background"],
        font={"color": colors["text"]},
        margin=dict(l=20, r=20, t=30, b=20),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.2,
            xanchor="center",
            x=0.5,
        ),
    )
    
    # Country distribution chart
    country_data = stats.get("countries", {})
    if not country_data:
        # Sample data for demonstration
        country_data = {
            "United States": 35,
            "China": 25,
            "Russia": 15,
            "Brazil": 10,
            "India": 5,
            "Germany": 3,
            "France": 2,
            "United Kingdom": 2,
            "Japan": 2,
            "South Korea": 1,
        }
    
    country_df = pd.DataFrame({
        "Country": list(country_data.keys()),
        "Count": list(country_data.values())
    })
    
    country_chart = px.bar(
        country_df,
        x="Country",
        y="Count",
        color="Count",
        color_continuous_scale=px.colors.sequential.Blues,
    )
    
    country_chart.update_layout(
        plot_bgcolor=colors["background"],
        paper_bgcolor=colors["background"],
        font={"color": colors["text"]},
        margin=dict(l=20, r=20, t=30, b=80),
        xaxis=dict(
            title="",
            tickangle=45,
        ),
        yaxis=dict(
            title="",
        ),
        coloraxis_showscale=False,
    )
    
    # Attack map
    connections = db.get_connections(limit=100)
    if not connections:
        # Sample data for demonstration
        connections = [
            {
                "src_ip": "203.0.113.1",
                "geo_location": {
                    "country": "United States",
                    "location": {"lat": 37.0902, "lon": -95.7129}
                },
                "protocol": "telnet"
            },
            {
                "src_ip": "203.0.113.2",
                "geo_location": {
                    "country": "China",
                    "location": {"lat": 35.8617, "lon": 104.1954}
                },
                "protocol": "http"
            },
            {
                "src_ip": "203.0.113.3",
                "geo_location": {
                    "country": "Russia",
                    "location": {"lat": 61.5240, "lon": 105.3188}
                },
                "protocol": "ssh"
            },
            {
                "src_ip": "203.0.113.4",
                "geo_location": {
                    "country": "Brazil",
                    "location": {"lat": -14.2350, "lon": -51.9253}
                },
                "protocol": "mqtt"
            },
            {
                "src_ip": "203.0.113.5",
                "geo_location": {
                    "country": "India",
                    "location": {"lat": 20.5937, "lon": 78.9629}
                },
                "protocol": "ftp"
            },
        ]
    
    # Extract geo locations
    geo_df = pd.DataFrame([
        {
            "lat": conn["geo_location"]["location"]["lat"],
            "lon": conn["geo_location"]["location"]["lon"],
            "country": conn["geo_location"]["country"],
            "ip": conn["src_ip"],
            "protocol": conn["protocol"],
        }
        for conn in connections
        if "geo_location" in conn and "location" in conn["geo_location"]
    ])
    
    if not geo_df.empty:
        attack_map = px.scatter_geo(
            geo_df,
            lat="lat",
            lon="lon",
            color="protocol",
            hover_name="ip",
            hover_data=["country", "protocol"],
            projection="natural earth",
            color_discrete_map={
                "telnet": colors["telnet"],
                "http": colors["http"],
                "ssh": colors["ssh"],
                "mqtt": colors["mqtt"],
                "ftp": colors["ftp"],
            },
        )
        
        attack_map.update_layout(
            plot_bgcolor=colors["background"],
            paper_bgcolor=colors["background"],
            font={"color": colors["text"]},
            margin=dict(l=0, r=0, t=0, b=0),
            geo=dict(
                showland=True,
                landcolor=colors["dark"],
                showocean=True,
                oceancolor=colors["background"],
                showcountries=True,
                countrycolor=colors["secondary"],
                showcoastlines=True,
                coastlinecolor=colors["secondary"],
                showframe=False,
                projection_type="natural earth",
            ),
        )
    else:
        # Empty map
        attack_map = go.Figure(go.Scattergeo())
        attack_map.update_layout(
            plot_bgcolor=colors["background"],
            paper_bgcolor=colors["background"],
            font={"color": colors["text"]},
            margin=dict(l=0, r=0, t=0, b=0),
            geo=dict(
                showland=True,
                landcolor=colors["dark"],
                showocean=True,
                oceancolor=colors["background"],
                showcountries=True,
                countrycolor=colors["secondary"],
                showcoastlines=True,
                coastlinecolor=colors["secondary"],
                showframe=False,
                projection_type="natural earth",
            ),
        )
    
    # Timeline chart
    # Group connections by hour
    if connections:
        timeline_data = {}
        for conn in connections:
            if "timestamp" in conn:
                try:
                    timestamp = datetime.datetime.fromisoformat(conn["timestamp"])
                    hour = timestamp.replace(minute=0, second=0, microsecond=0)
                    hour_str = hour.isoformat()
                    
                    if hour_str not in timeline_data:
                        timeline_data[hour_str] = {
                            "telnet": 0,
                            "http": 0,
                            "ssh": 0,
                            "mqtt": 0,
                            "ftp": 0,
                        }
                    
                    protocol = conn.get("protocol", "other")
                    if protocol in timeline_data[hour_str]:
                        timeline_data[hour_str][protocol] += 1
                except (ValueError, TypeError):
                    pass
        
        # Convert to DataFrame
        timeline_rows = []
        for hour_str, protocols in timeline_data.items():
            for protocol, count in protocols.items():
                timeline_rows.append({
                    "hour": hour_str,
                    "protocol": protocol,
                    "count": count,
                })
        
        timeline_df = pd.DataFrame(timeline_rows)
        
        if not timeline_df.empty:
            timeline_chart = px.line(
                timeline_df,
                x="hour",
                y="count",
                color="protocol",
                color_discrete_map={
                    "telnet": colors["telnet"],
                    "http": colors["http"],
                    "ssh": colors["ssh"],
                    "mqtt": colors["mqtt"],
                    "ftp": colors["ftp"],
                },
            )
            
            timeline_chart.update_layout(
                plot_bgcolor=colors["background"],
                paper_bgcolor=colors["background"],
                font={"color": colors["text"]},
                margin=dict(l=20, r=20, t=30, b=50),
                xaxis=dict(
                    title="",
                    showgrid=True,
                    gridcolor=colors["secondary"],
                ),
                yaxis=dict(
                    title="",
                    showgrid=True,
                    gridcolor=colors["secondary"],
                ),
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=-0.2,
                    xanchor="center",
                    x=0.5,
                ),
            )
        else:
            # Empty timeline
            timeline_chart = go.Figure()
            timeline_chart.update_layout(
                plot_bgcolor=colors["background"],
                paper_bgcolor=colors["background"],
                font={"color": colors["text"]},
                margin=dict(l=20, r=20, t=30, b=50),
                xaxis=dict(
                    title="",
                    showgrid=True,
                    gridcolor=colors["secondary"],
                ),
                yaxis=dict(
                    title="",
                    showgrid=True,
                    gridcolor=colors["secondary"],
                ),
            )
    else:
        # Sample data for demonstration
        hours = [
            (datetime.datetime.now() - datetime.timedelta(hours=i)).isoformat()
            for i in range(24, 0, -1)
        ]
        
        import random
        timeline_rows = []
        for hour in hours:
            for protocol in ["telnet", "http", "ssh", "mqtt", "ftp"]:
                count = random.randint(0, 10)
                if count > 0:
                    timeline_rows.append({
                        "hour": hour,
                        "protocol": protocol,
                        "count": count,
                    })
        
        timeline_df = pd.DataFrame(timeline_rows)
        
        timeline_chart = px.line(
            timeline_df,
            x="hour",
            y="count",
            color="protocol",
            color_discrete_map={
                "telnet": colors["telnet"],
                "http": colors["http"],
                "ssh": colors["ssh"],
                "mqtt": colors["mqtt"],
                "ftp": colors["ftp"],
            },
        )
        
        timeline_chart.update_layout(
            plot_bgcolor=colors["background"],
            paper_bgcolor=colors["background"],
            font={"color": colors["text"]},
            margin=dict(l=20, r=20, t=30, b=50),
            xaxis=dict(
                title="",
                showgrid=True,
                gridcolor=colors["secondary"],
            ),
            yaxis=dict(
                title="",
                showgrid=True,
                gridcolor=colors["secondary"],
            ),
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=-0.2,
                xanchor="center",
                x=0.5,
            ),
        )
    
    # Connections table
    connections_data = []
    connections_columns = [
        {"name": "Time", "id": "timestamp"},
        {"name": "Source IP", "id": "src_ip"},
        {"name": "Port", "id": "dst_port"},
        {"name": "Protocol", "id": "protocol"},
        {"name": "Country", "id": "country"},
    ]
    
    if connections:
        for conn in connections[:10]:  # Limit to 10 connections
            connections_data.append({
                "timestamp": conn.get("timestamp", ""),
                "src_ip": conn.get("src_ip", ""),
                "dst_port": conn.get("dst_port", ""),
                "protocol": conn.get("protocol", ""),
                "country": conn.get("geo_location", {}).get("country", ""),
            })
    else:
        # Sample data for demonstration
        connections_data = [
            {
                "timestamp": "2025-05-25T19:30:00",
                "src_ip": "203.0.113.1",
                "dst_port": 8023,
                "protocol": "telnet",
                "country": "United States",
            },
            {
                "timestamp": "2025-05-25T19:25:00",
                "src_ip": "203.0.113.2",
                "dst_port": 8080,
                "protocol": "http",
                "country": "China",
            },
            {
                "timestamp": "2025-05-25T19:20:00",
                "src_ip": "203.0.113.3",
                "dst_port": 2222,
                "protocol": "ssh",
                "country": "Russia",
            },
            {
                "timestamp": "2025-05-25T19:15:00",
                "src_ip": "203.0.113.4",
                "dst_port": 1883,
                "protocol": "mqtt",
                "country": "Brazil",
            },
            {
                "timestamp": "2025-05-25T19:10:00",
                "src_ip": "203.0.113.5",
                "dst_port": 2121,
                "protocol": "ftp",
                "country": "India",
            },
        ]
    
    # Auth table
    auth_attempts = db.get_auth_attempts(limit=10)
    auth_data = []
    auth_columns = [
        {"name": "Time", "id": "timestamp"},
        {"name": "Source IP", "id": "src_ip"},
        {"name": "Username", "id": "username"},
        {"name": "Password", "id": "password"},
        {"name": "Protocol", "id": "protocol"},
        {"name": "Success", "id": "success"},
    ]
    
    if auth_attempts:
        for auth in auth_attempts[:10]:  # Limit to 10 auth attempts
            auth_data.append({
                "timestamp": auth.get("timestamp", ""),
                "src_ip": auth.get("src_ip", ""),
                "username": auth.get("username", ""),
                "password": auth.get("password", ""),
                "protocol": auth.get("protocol", ""),
                "success": auth.get("success", False),
            })
    else:
        # Sample data for demonstration
        auth_data = [
            {
                "timestamp": "2025-05-25T19:30:00",
                "src_ip": "203.0.113.1",
                "username": "admin",
                "password": "admin",
                "protocol": "telnet",
                "success": True,
            },
            {
                "timestamp": "2025-05-25T19:25:00",
                "src_ip": "203.0.113.2",
                "username": "root",
                "password": "password",
                "protocol": "ssh",
                "success": False,
            },
            {
                "timestamp": "2025-05-25T19:20:00",
                "src_ip": "203.0.113.3",
                "username": "admin",
                "password": "12345",
                "protocol": "ftp",
                "success": False,
            },
            {
                "timestamp": "2025-05-25T19:15:00",
                "src_ip": "203.0.113.4",
                "username": "user",
                "password": "user123",
                "protocol": "telnet",
                "success": True,
            },
            {
                "timestamp": "2025-05-25T19:10:00",
                "src_ip": "203.0.113.5",
                "username": "administrator",
                "password": "admin123",
                "protocol": "ssh",
                "success": False,
            },
        ]
    
    return (
        last_update,
        connections_count,
        auth_count,
        commands_count,
        http_count,
        vulnerabilities_count,
        malware_count,
        protocol_chart,
        country_chart,
        attack_map,
        timeline_chart,
        connections_data,
        connections_columns,
        auth_data,
        auth_columns,
    )

def run_dashboard(host: str = "0.0.0.0", port: int = 8050, debug: bool = False) -> None:
    """
    Run the dashboard application.
    
    Args:
        host: Host to bind to
        port: Port to bind to
        debug: Whether to run in debug mode
    """
    app.run_server(host=host, port=port, debug=debug)

if __name__ == "__main__":
    run_dashboard()