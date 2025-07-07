import dash
from dash import dcc, html, Input, Output
import pandas as pd
import plotly.express as px

# Normalize column names to lowercase and replace spaces with underscores
def normalize_columns(df):
    df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')
    return df

# Set y-axis range dynamically based on data max value (plus padding)
def set_yaxis_padding(fig, y_col, df):
    if df.empty or y_col not in df.columns:
        return fig
    max_val = df[y_col].max()
    fig.update_yaxes(range=[0, max_val * 1.1])  # 10% padding above max
    return fig

# Load and normalize all datasets
web_logs = normalize_columns(pd.read_excel("Dataset 1__Web_Server_Access_Logs.xlsx"))
user_auth = normalize_columns(pd.read_csv("Dataset 2__User_Authentication_logs.csv"))
malware = normalize_columns(pd.read_csv("Dataset 3__Malware_Threat_Alerts.csv"))
network = normalize_columns(pd.read_csv("Dataset 4__Network_Traffic_Summary.csv"))
incidents = normalize_columns(pd.read_csv("Dataset 5__Security_Incident_Reports.csv"))

# Initialize App
app = dash.Dash(__name__, suppress_callback_exceptions=True)
app.title = "Everything Organic - Dashboard for Capstone"

# Layout app
app.layout = html.Div([
    html.H1("Everything Organic Security Posture", style={'textAlign': 'center'}),

    # Define 3 main features
    dcc.Tabs(id="tabs", value='tab1', children=[
        dcc.Tab(label='Threat Landscape', value='tab1'),
        dcc.Tab(label='User Behavior & Access', value='tab2'),
        dcc.Tab(label='Vulnerability & Compliance', value='tab3'),
    ]),

    html.Div(id='tabs-content') 
])

# update content based on tab selection
@app.callback(Output('tabs-content', 'children'), Input('tabs', 'value'))
def render_content(tab):
    try:
        # FIRST TAB : THREAT LANDSCAPE
        if tab == 'tab1':
            # Parse detection timestamps and remove bad rows
            malware['detection_time'] = pd.to_datetime(malware['detection_time'], errors='coerce')
            malware_clean = malware.dropna(subset=['detection_time'])

            if malware_clean.empty:
                return html.Div("No malware detection data available.")

            # Line chart of malware detections over time --> rolling avg line included
            daily_counts = malware_clean.groupby(malware_clean['detection_time'].dt.date).size().reset_index(name='count')
            daily_counts['rolling_avg'] = daily_counts['count'].rolling(window=7, min_periods=1).mean()

            fig_trend = px.line(daily_counts, x='detection_time', y='count', title='Malware Detections Over Time')
            
            fig_trend.data[0].name = "Daily Count"
            fig_trend.data[0].showlegend = True
            fig_trend.add_scatter(x=daily_counts['detection_time'], y=daily_counts['rolling_avg'], mode='lines', name='Weekly Average')

            
            # Bar chart of severity levels
            severity_counts = malware['severity'].value_counts().reset_index()
            severity_counts.columns = ['severity', 'count']
            fig_severity = px.bar(severity_counts, x='severity', y='count', title='Malware Severity Distribution')
            fig_severity = set_yaxis_padding(fig_severity, 'count', severity_counts)

            # Table of most recent critical/high threats
            critical_levels = ['Critical', 'High']
            recent_critical = malware_clean[malware_clean['severity'].isin(critical_levels)].sort_values('detection_time', ascending=False).head(10)

            recent_critical_table = html.Table([
                html.Thead(html.Tr([html.Th(col.replace('_', ' ').title()) for col in ['detection_time', 'threat_type', 'affected_file', 'remediation_status']])),
                html.Tbody([
                    html.Tr([html.Td(recent_critical.iloc[i][col]) for col in ['detection_time', 'threat_type', 'affected_file', 'remediation_status']])
                    for i in range(len(recent_critical))
                ])
            ], style={'width':'100%', 'border': '1px solid black', 'borderCollapse': 'collapse'})

            return html.Div([
                html.H3("Threat Landscape"),
                dcc.Graph(figure=fig_trend),
                dcc.Graph(figure=fig_severity),
                html.H4("Recent Critical/High Threats"),
                recent_critical_table,
            ])

        # SECOND TAB : USER BEHAVIOR AND ACCESS
        elif tab == 'tab2':
            # Login attempt parsing
            user_auth['login_timestamp'] = pd.to_datetime(user_auth['login_timestamp'], errors='coerce')
            user_auth_clean = user_auth.dropna(subset=['login_timestamp'])

            if user_auth_clean.empty:
                return html.Div("No user authentication data available.")

            # login attempts by day (grouped by success/failure) -- bar chart
            daily_logins = user_auth_clean.groupby([user_auth_clean['login_timestamp'].dt.date, 'login_status']).size().reset_index(name='count')
            fig_login_attempts = px.bar(daily_logins, x='login_timestamp', y='count', color='login_status', barmode='group',
                                       title='Login Attempts Over Time')
            fig_login_attempts = set_yaxis_padding(fig_login_attempts, 'count', daily_logins)

            # top 5 users with most failed logins -- bar chart
            failed_logins = user_auth_clean[user_auth_clean['login_status'] == 'Failure']
            failed_by_user = failed_logins['username'].value_counts().head(5).reset_index()
            failed_by_user.columns = ['username', 'fail_count']
            fig_failed = px.bar(failed_by_user, x='username', y='fail_count', title='Top Users with Failed Logins')
            fig_failed = set_yaxis_padding(fig_failed, 'fail_count', failed_by_user)

            # top 5 users by login success rate -- bar chart
            success_counts = user_auth_clean.groupby(['username', 'login_status']).size().unstack(fill_value=0)
            success = success_counts.get('Success', pd.Series(0, index=success_counts.index))
            failure = success_counts.get('Failure', pd.Series(0, index=success_counts.index))
            total = success + failure
            success_rate = success / total.replace(0, 1)
            top_success = success_rate.sort_values(ascending=False).head(5).reset_index()

            fig_success = px.bar(top_success, x='username', y=0, labels={0: 'success_rate'}, title='Top User Login Success Rates')
            fig_success = set_yaxis_padding(fig_success, 0, top_success)

            return html.Div([
                html.H3("User Behavior & Access"),
                dcc.Graph(figure=fig_login_attempts),
                dcc.Graph(figure=fig_failed),
                dcc.Graph(figure=fig_success),
            ])

        # THIRD TAB : VULNERABILITY AND COMPLIANCE
        elif tab == 'tab3':
            # Parse incident report timestamps
            incidents['report_time'] = pd.to_datetime(incidents['report_time'], errors='coerce')
            incidents_clean = incidents.dropna(subset=['report_time'])

            if incidents_clean.empty:
                return html.Div("No incident report data available.")

            # count of incidents by category -- bar chart
            category_counts = incidents_clean['category'].value_counts().reset_index()
            category_counts.columns = ['category', 'count']
            fig_cat = px.bar(category_counts, x='category', y='count', title='Incident Counts by Category')
            fig_cat = set_yaxis_padding(fig_cat, 'count', category_counts)

            # count of incidents by resolution status -- bar chart
            res_status_counts = incidents_clean['resolution_status'].value_counts().reset_index()
            res_status_counts.columns = ['status', 'count']
            fig_res_status = px.bar(res_status_counts, x='status', y='count', title='Incident Resolution Status')
            fig_res_status = set_yaxis_padding(fig_res_status, 'count', res_status_counts)

            # most recent incidents
            open_incidents = incidents_clean[incidents_clean['resolution_status'].str.lower() != 'resolved'].sort_values('report_time', ascending=False).head(10)
            open_incidents_table = html.Table([
                html.Thead(html.Tr([html.Th(col.replace('_', ' ').title()) for col in ['incident_id', 'report_time', 'category', 'detected_by', 'resolution_status']])),
                html.Tbody([
                    html.Tr([html.Td(open_incidents.iloc[i][col]) for col in ['incident_id', 'report_time', 'category', 'detected_by', 'resolution_status']])
                    for i in range(len(open_incidents))
                ])
            ], style={'width':'100%', 'border': '1px solid black', 'borderCollapse': 'collapse'})

            return html.Div([
                html.H3("Vulnerability & Compliance"),
                dcc.Graph(figure=fig_cat),
                dcc.Graph(figure=fig_res_status),
                html.H4("Recent Open Incidents"),
                open_incidents_table,
            ])

        # fallback
        else:
            return html.Div("Please select a tab.")

    # Display if there is an error.
    except Exception as e:
        return html.Div([
            html.H3("Error loading tab content"),
            html.Pre(str(e))
        ])

# RUN APP PLEASE PLEASE PLEASE WORK PLEASE IM BEGGING
if __name__ == '__main__':
    app.run(debug=True)
