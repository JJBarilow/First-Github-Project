# =======================
# Import libraries
# =======================
import dash                         # Core Dash package
from dash import dcc, html, Input, Output  # Dash components and callback handling
import pandas as pd                # For data manipulation
import plotly.express as px        # For interactive visualizations



# Normalize column names (remove whitespace, lowercase, replace spaces with underscores Example 1 --> Example_1
def normalize_columns(df):
    df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')
    return df

# scale the y-axis based on the max values
def set_yaxis_padding(fig, y_col, df):
    if df.empty or y_col not in df.columns:
        return fig
    max_val = df[y_col].max()
    fig.update_yaxes(range=[0, max_val * 1.1])
    return fig

# ==========================
# Load and Clean Data
# ==========================

# Read and normalize all five datasets
web_logs = normalize_columns(pd.read_excel("Dataset 1__Web_Server_Access_Logs.xlsx"))
user_auth = normalize_columns(pd.read_csv("Dataset 2__User_Authentication_logs.csv"))
malware = normalize_columns(pd.read_csv("Dataset 3__Malware_Threat_Alerts.csv"))
network = normalize_columns(pd.read_csv("Dataset 4__Network_Traffic_Summary.csv"))
incidents = normalize_columns(pd.read_csv("Dataset 5__Security_Incident_Reports.csv"))

# ==========================
# Initialize Dash App
# ==========================

app = dash.Dash(__name__, suppress_callback_exceptions=True)
app.title = "Everything Organic - Dashboard for Capstone"

# app layout with tabs for different dashboard views
app.layout = html.Div([
    html.H1("Everything Organic Security Posture", style={'textAlign': 'center'}),
    
    # Tabs across the top for navigation
    dcc.Tabs(id="tabs", value='tab1', children=[
        dcc.Tab(label='Threat Landscape', value='tab1'),
        dcc.Tab(label='User Behavior & Access', value='tab2'),
        dcc.Tab(label='Vulnerability & Compliance', value='tab3'),
    ]),

    # Placeholder for dynamic tab content
    html.Div(id='tabs-content')
])

# ==========================
# Callback to Render Tab Content
# ==========================
@app.callback(Output('tabs-content', 'children'), Input('tabs', 'value'))
def render_content(tab):
    try:
        # -------------------------------
        # Tab 1: Threat Landscape
        # -------------------------------
        if tab == 'tab1':
            # Convert detection time to datetime format
            malware['detection_time'] = pd.to_datetime(malware['detection_time'], errors='coerce')
            malware_clean = malware.dropna(subset=['detection_time'])

            if malware_clean.empty:
                return html.Div("No malware detection data available.")

            # Count daily detections and calculate weekly detections
            daily_counts = malware_clean.groupby(malware_clean['detection_time'].dt.date).size().reset_index(name='count')
            daily_counts['rolling_avg'] = daily_counts['count'].rolling(window=7, min_periods=1).mean()

            # Create line chart of daily detections
            fig_trend = px.line(daily_counts, x='detection_time', y='count')
            fig_trend.data[0].name = "Daily Count"
            fig_trend.data[0].showlegend = True
            fig_trend.add_scatter(x=daily_counts['detection_time'], y=daily_counts['rolling_avg'], mode='lines', name='Weekly Average')
            fig_trend.update_xaxes(tickmode='linear', dtick=86400000.0, tickformat='%b %d', tickangle=45)  # Show every date

            # Create bar chart of malware severity counts
            severity_counts = malware['severity'].value_counts().reset_index()
            severity_counts.columns = ['severity', 'count']
            fig_severity = px.bar(severity_counts, x='severity', y='count')
            fig_severity = set_yaxis_padding(fig_severity, 'count', severity_counts)

            # Create table of recent critical/high severity threats
            critical_levels = ['Critical', 'High']
            recent_critical = malware_clean[malware_clean['severity'].isin(critical_levels)].sort_values('detection_time', ascending=False).head(10)
            recent_critical_table = html.Table([
                html.Thead(html.Tr([html.Th(col.replace('_', ' ').title()) for col in ['detection_time', 'threat_type', 'affected_file', 'remediation_status']])),
                html.Tbody([
                    html.Tr([html.Td(recent_critical.iloc[i][col]) for col in ['detection_time', 'threat_type', 'affected_file', 'remediation_status']])
                    for i in range(len(recent_critical))
                ])
            ], style={'width': '100%', 'border': '1px solid black', 'borderCollapse': 'collapse'})

            # Return all elements for first tab
            return html.Div([
                html.H3("Threat Landscape"),

                html.Div([
                    html.H4("Malware Detections Over Time"),
                    html.P("This line chart shows daily malware detections with a weekly average after each day.",
                           style={'fontSize': '13px', 'color': '#666', 'marginTop': '-10px', 'marginBottom': '10px', 'textAlign': 'center'}),
                    dcc.Graph(figure=fig_trend),
                ]),

                html.Div([
                    html.H4("Malware Severity Distribution"),
                    html.P("This chart shows how malware detections are distributed across severity levels.",
                           style={'fontSize': '13px', 'color': '#666', 'marginTop': '-10px', 'marginBottom': '10px', 'textAlign': 'center'}),
                    dcc.Graph(figure=fig_severity),
                ]),

                html.H4("Recent Critical/High Threats", style={'marginTop': '30px'}),
                html.P("Table showing the 10 most recent malware detections with a severity rating of High or Critical along with what they affected, as well as their remediation statuses.",
                       style={'textAlign': 'center', 'fontSize': '14px', 'marginBottom': '10px', 'color': '#666'}),
                recent_critical_table,
            ])

        # -------------------------------
        # Tab 2: User Behavior & Access
        # -------------------------------
        elif tab == 'tab2':
            # Clean timestamps and drop invalid ones
            user_auth['login_timestamp'] = pd.to_datetime(user_auth['login_timestamp'], errors='coerce')
            user_auth_clean = user_auth.dropna(subset=['login_timestamp'])

            if user_auth_clean.empty:
                return html.Div("No user authentication data available.")

            # Group login attempts by date and status (Success/Failure)
            daily_logins = user_auth_clean.groupby([user_auth_clean['login_timestamp'].dt.date, 'login_status']).size().reset_index(name='count')
            fig_login_attempts = px.bar(daily_logins, x='login_timestamp', y='count', color='login_status', barmode='group')
            fig_login_attempts = set_yaxis_padding(fig_login_attempts, 'count', daily_logins)

            #  Force every date to display on x-axis
            fig_login_attempts.update_xaxes(tickmode='linear', dtick=86400000.0, tickformat='%b %d', tickangle=45)

            # Bar chart: Top users with failed login attempts
            failed_logins = user_auth_clean[user_auth_clean['login_status'] == 'Failure']
            failed_by_user = failed_logins['username'].value_counts().head(5).reset_index()
            failed_by_user.columns = ['username', 'fail_count']
            fig_failed = px.bar(failed_by_user, x='username', y='fail_count')
            fig_failed = set_yaxis_padding(fig_failed, 'fail_count', failed_by_user)

            # Bar chart: Users with highest login success rates
            success_counts = user_auth_clean.groupby(['username', 'login_status']).size().unstack(fill_value=0)
            success = success_counts.get('Success', pd.Series(0, index=success_counts.index))
            failure = success_counts.get('Failure', pd.Series(0, index=success_counts.index))
            total = success + failure
            success_rate = success / total.replace(0, 1)
            top_success = success_rate.sort_values(ascending=False).head(5).reset_index()

            # Convert success_rate to percentage for the y-axis and update labels accordingly
            top_success['success_rate_percent'] = top_success[0] * 100
            fig_success = px.bar(top_success, x='username', y='success_rate_percent', labels={'success_rate_percent': 'Success Rate (%)'})

            fig_success.update_yaxes(ticksuffix='%')  # Add % sign on y-axis tick labels

            fig_success = set_yaxis_padding(fig_success, 'success_rate_percent', top_success)

            # Return charts for second tab
            return html.Div([
                html.H3("User Behavior & Access"),

                html.Div([
                    html.H4("Login Attempts Over Time"),
                    html.P("This chart shows daily login activity grouped by success and failure.",
                           style={'fontSize': '13px', 'color': '#666', 'marginTop': '-10px', 'marginBottom': '10px', 'textAlign': 'center'}),
                    dcc.Graph(figure=fig_login_attempts),
                ]),

                html.Div([
                    html.H4("Top Users with Failed Logins"),
                    html.P("Displays the top 5 users with the most failed login attempts.",
                           style={'fontSize': '13px', 'color': '#666', 'marginTop': '-10px', 'marginBottom': '10px', 'textAlign': 'center'}),
                    dcc.Graph(figure=fig_failed),
                ]),

                html.Div([
                    html.H4("Top User Login Success Rates"),
                    html.P("Shows users with the highest login success rates.",
                           style={'fontSize': '13px', 'color': '#666', 'marginTop': '-10px', 'marginBottom': '10px', 'textAlign': 'center'}),
                    dcc.Graph(figure=fig_success),
                ]),
            ])

        # -------------------------------
        # Tab 3: Vulnerability & Compliance
        # -------------------------------
        elif tab == 'tab3':
            incidents['report_time'] = pd.to_datetime(incidents['report_time'], errors='coerce')
            incidents_clean = incidents.dropna(subset=['report_time'])

            if incidents_clean.empty:
                return html.Div("No incident report data available.")

            # Bar chart: Number of incidents per category
            category_counts = incidents_clean['category'].value_counts().reset_index()
            category_counts.columns = ['category', 'count']
            fig_cat = px.bar(category_counts, x='category', y='count', title='Incident Counts by Category')
            fig_cat = set_yaxis_padding(fig_cat, 'count', category_counts)

            # Bar chart: Incident resolution statuses
            res_status_counts = incidents_clean['resolution_status'].value_counts().reset_index()
            res_status_counts.columns = ['status', 'count']
            fig_res_status = px.bar(res_status_counts, x='status', y='count', title='Incident Resolution Status')
            fig_res_status = set_yaxis_padding(fig_res_status, 'count', res_status_counts)

            # Table: 10 most recent open (unresolved) incidents
            open_incidents = incidents_clean[incidents_clean['resolution_status'].str.lower() != 'resolved'].sort_values('report_time', ascending=False).head(10)
            open_incidents_table = html.Table([
                html.Thead(html.Tr([html.Th(col.replace('_', ' ').title()) for col in ['incident_id', 'report_time', 'category', 'detected_by', 'resolution_status']])),
                html.Tbody([
                    html.Tr([html.Td(open_incidents.iloc[i][col]) for col in ['incident_id', 'report_time', 'category', 'detected_by', 'resolution_status']])
                    for i in range(len(open_incidents))
                ])
            ], style={'width': '100%', 'border': '1px solid black', 'borderCollapse': 'collapse'})

            return html.Div([
                html.H3("Vulnerability & Compliance"),
                dcc.Graph(figure=fig_cat),
                dcc.Graph(figure=fig_res_status),
                html.H4("Recent Open Incidents"),
                open_incidents_table,
            ])

        else:
            return html.Div("Please select a tab.")

    # Show error if something breaks
    except Exception as e:
        return html.Div([
            html.H3("Error loading tab content"),
            html.Pre(str(e))
        ])

# ==========================
# Run the Dash App
# ==========================
if __name__ == '__main__':
    app.run(debug=True)
