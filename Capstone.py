import dash
from dash import dcc, html, Input, Output

# start app
app = dash.Dash(__name__, suppress_callback_exceptions=True)
app.title = "Everything Organic - Capstone Dashboard"

# layout
app.layout = html.Div([
    html.H1("Everything Organic Security Posture", style={'textAlign': 'center'}),

    dcc.Tabs(id="tabs", value='tab1', children=[
        dcc.Tab(label='Threat Landscape', value='tab1'),
        dcc.Tab(label='User Behavior & Access', value='tab2'),
        dcc.Tab(label='Vulnerability & Compliance', value='tab3'),
    ]),

    html.Div(id='tabs-content')
])

# switching tabs 
@app.callback(Output('tabs-content', 'children'), Input('tabs', 'value'))
def render_content(tab):
    if tab == 'tab1':
        return html.Div([
            html.H3("Threat Landscape"),
            html.Ul([
                html.Li("View malware trends"),
                html.Li("Analyze severity distribution"),
                html.Li("Identify top source IPs"),
            ])
        ])

    elif tab == 'tab2':
        return html.Div([
            html.H3("User Behavior & Access"),
            html.Ul([
                html.Li("Visualize login attempts"),
                html.Li("Monitor failed logins"),
                html.Li("Evaluate user success rates"),
            ])
        ])

    elif tab == 'tab3':
        return html.Div([
            html.H3("Vulnerability & Compliance"),
            html.Ul([
                html.Li("Track incident types"),
                html.Li("View resolution times"),
                html.Li("Check compliance indicators"),
            ])
        ])

if __name__ == '__main__':
    app.run(debug=True)
