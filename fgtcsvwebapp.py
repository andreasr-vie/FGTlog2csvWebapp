from flask import Flask, request, redirect, url_for, send_file, render_template_string, flash
import re
import pandas as pd
from io import BytesIO

app = Flask(__name__)
app.secret_key = 'your_secret_key'


# Define the regex patterns for different log entries
patterns = {
    'pattern1': re.compile(
        r'date=(?P<date>\d{4}-\d{2}-\d{2})\s+'
        r'time=(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'eventtime=(?P<eventtime>\d+)\s+'
        r'tz="(?P<tz>[^"]+)"\s+'
        r'logid="(?P<logid>\d+)"\s+'
        r'type="(?P<type>[^"]+)"\s+'
        r'subtype="(?P<subtype>[^"]+)"\s+'
        r'eventtype="(?P<eventtype>[^"]+)"\s+'
        r'level="(?P<level>[^"]+)"\s+'
        r'vd="(?P<vd>[^"]+)"\s+'
        r'policyid=(?P<policyid>\d+)\s+'
        r'poluuid="(?P<poluuid>[^"]+)"\s+'
        r'policytype="(?P<policytype>[^"]+)"\s+'
        r'sessionid=(?P<sessionid>\d+)\s+'
        r'srcip=(?P<srcip>\d{1,3}(?:\.\d{1,3}){3})\s+'
        r'srcport=(?P<srcport>\d+)\s+'
        r'srccountry="(?P<srccountry>[^"]+)"\s+'
        r'srcintf="(?P<srcintf>[^"]+)"\s+'
        r'srcintfrole="(?P<srcintfrole>[^"]+)"\s+'
        r'srcuuid="(?P<srcuuid>[^"]+)"\s+'
        r'dstip=(?P<dstip>\d{1,3}(?:\.\d{1,3}){3})\s+'
        r'dstport=(?P<dstport>\d+)\s+'
        r'dstcountry="(?P<dstcountry>[^"]+)"\s+'
        r'dstintf="(?P<dstintf>[^"]+)"\s+'
        r'dstintfrole="(?P<dstintfrole>[^"]+)"\s+'
        r'dstuuid="(?P<dstuuid>[^"]+)"\s+'
        r'proto=(?P<proto>\d+)\s+'
        r'service="(?P<service>[^"]+)"\s+'
        r'hostname="(?P<hostname>[^"]+)"\s+'
        r'profile="(?P<profile>[^"]+)"\s+'
        r'action="(?P<action>[^"]+)"\s+'
        r'reqtype="(?P<reqtype>[^"]+)"\s+'
        r'url="(?P<url>[^"]+)"\s+'
        r'sentbyte=(?P<sentbyte>\d+)\s+'
        r'rcvdbyte=(?P<rcvdbyte>\d+)\s+'
        r'direction="(?P<direction>[^"]+)"\s+'
        r'msg="(?P<msg>[^"]+)"\s+'
        r'ratemethod="(?P<ratemethod>[^"]+)"\s+'
        r'cat=(?P<cat>\d+)\s+'
        r'catdesc="(?P<catdesc>[^"]+)"'
    ),
    'pattern2': re.compile(
        r'date=(?P<date>\d{4}-\d{2}-\d{2})\s+'
        r'time=(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'eventtime=(?P<eventtime>\d+)\s+'
        r'tz="(?P<tz>[^"]+)"\s+'
        r'logid="(?P<logid>\d+)"\s+'
        r'type="(?P<type>[^"]+)"\s+'
        r'subtype="(?P<subtype>[^"]+)"\s+'
        r'eventtype="(?P<eventtype>[^"]+)"\s+'
        r'level="(?P<level>[^"]+)"\s+'
        r'vd="(?P<vd>[^"]+)"\s+'
        r'severity="(?P<severity>[^"]+)"\s+'
        r'srcip=(?P<srcip>\d{1,3}(?:\.\d{1,3}){3})\s+'
        r'srccountry="(?P<srccountry>[^"]+)"\s+'
        r'dstip=(?P<dstip>\d{1,3}(?:\.\d{1,3}){3})\s+'
        r'dstcountry="(?P<dstcountry>[^"]+)"\s+'
        r'srcintf="(?P<srcintf>[^"]+)"\s+'
        r'srcintfrole="(?P<srcintfrole>[^"]+)"\s+'
        r'dstintf="(?P<dstintf>[^"]+)"\s+'
        r'dstintfrole="(?P<dstintfrole>[^"]+)"\s+'
        r'sessionid=(?P<sessionid>\d+)\s+'
        r'action="(?P<action>[^"]+)"\s+'
        r'proto=(?P<proto>\d+)\s+'
        r'service="(?P<service>[^"]+)"\s+'
        r'policyid=(?P<policyid>\d+)\s+'
        r'poluuid="(?P<poluuid>[^"]+)"\s+'
        r'policytype="(?P<policytype>[^"]+)"\s+'
        r'attack="(?P<attack>[^"]+)"\s+'
        r'srcport=(?P<srcport>\d+)\s+'
        r'dstport=(?P<dstport>\d+)\s+'
        r'hostname="(?P<hostname>[^"]+)"\s+'
        r'url="(?P<url>[^"]+)"\s+'
        r'agent="(?P<agent>[^"]+)"\s+'
        r'httpmethod="(?P<httpmethod>[^"]+)"\s+'
        r'direction="(?P<direction>[^"]+)"\s+'
        r'attackid=(?P<attackid>\d+)\s+'
        r'profile="(?P<profile>[^"]+)"'
    ),
    'pattern3': re.compile(
        r'date=(?P<date>\d{4}-\d{2}-\d{2})\s+'
        r'time=(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'eventtime=(?P<eventtime>\d+)\s+'
        r'tz="(?P<tz>[^"]+)"\s+'
        r'logid="(?P<logid>\d+)"\s+'
        r'type="(?P<type>[^"]+)"\s+'
        r'subtype="(?P<subtype>[^"]+)"\s+'
        r'eventtype="(?P<eventtype>[^"]+)"\s+'
        r'level="(?P<level>[^"]+)"\s+'
        r'vd="(?P<vd>[^"]+)"\s+'
        r'appid=(?P<appid>\d+)\s+'
        r'srcip=(?P<srcip>\d{1,3}(?:\.\d{1,3}){3})\s+'
        r'srccountry="(?P<srccountry>[^"]+)"\s+'
        r'dstip=(?P<dstip>\d{1,3}(?:\.\d{1,3}){3})\s+'
        r'dstcountry="(?P<dstcountry>[^"]+)"\s+'
        r'srcport=(?P<srcport>\d+)\s+'
        r'dstport=(?P<dstport>\d+)\s+'
        r'srcintf="(?P<srcintf>[^"]+)"\s+'
        r'srcintfrole="(?P<srcintfrole>[^"]+)"\s+'
        r'dstintf="(?P<dstintf>[^"]+)"\s+'
        r'dstintfrole="(?P<dstintfrole>[^"]+)"\s+'
        r'proto=(?P<proto>\d+)\s+'
        r'service="(?P<service>[^"]+)"\s+'
        r'direction="(?P<direction>[^"]+)"\s+'
        r'policyid=(?P<policyid>\d+)\s+'
        r'poluuid="(?P<poluuid>[^"]+)"\s+'
        r'policytype="(?P<policytype>[^"]+)"\s+'
        r'sessionid=(?P<sessionid>\d+)\s+'
        r'applist="(?P<applist>[^"]+)"\s+'
        r'action="(?P<action>[^"]+)"\s+'
        r'appcat="(?P<appcat>[^"]+)"\s+'
        r'app="(?P<app>[^"]+)"\s+'
        r'hostname="(?P<hostname>[^"]+)"\s+'
        r'incidentserialno=(?P<incidentserialno>\d+)\s+'
        r'url="(?P<url>[^"]+)"\s+'
        r'msg="(?P<msg>[^"]+)"\s+'
        r'apprisk="(?P<apprisk>[^"]+)"\s+'
        r'scertcname="(?P<scertcname>[^"]+)"'
    ),
}

@app.route('/')
def upload_file():
    return render_template_string('''
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <title>FortiGate Log File Converter</title>
        <style>
            body { padding-top: 40px; }
            .container { max-width: 600px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1 class="text-center">FortiGate Logfile to CSV Converter</h1>
            {% with messages = get_flashed_messages() %}
              {% if messages %}
                <div class="alert alert-warning">
                  {% for message in messages %}
                    <p>{{ message }}</p>
                  {% endfor %}
                </div>
              {% endif %}
            {% endwith %}
            <form action="/process" method="post" enctype="multipart/form-data" class="mt-4">
                <div class="form-group">
                    <label for="file">Upload log file and select log type</label>
                    <input type="file" class="form-control-file" id="file" name="file" required>
                </div>
                <div class="form-group">
                    <label for="pattern">Log type</label>
                    <select class="form-control" id="pattern" name="pattern">
                        <option value="pattern1">Webfilter</option>
                        <option value="pattern2">IPS</option>
                        <option value="pattern3">Application Control</option>
                    </select>
                </div>
                <button type="submit" class="btn btn-primary btn-block">Convert</button>
            </form>
        </div>
        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.3/dist/umd/popper.min.js"></script>
        <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    </body>
    </html>
    ''')

@app.route('/process', methods=['POST'])
def process_file():
    if 'file' not in request.files or not request.files['file'].filename:
        flash('No file uploaded.')
        return redirect(url_for('upload_file'))

    file = request.files['file']
    pattern_choice = request.form['pattern']
    pattern = patterns.get(pattern_choice)

    if not pattern:
        flash('Invalid log type selected.')
        return redirect(url_for('upload_file'))

    try:
        log_entries = file.read().decode('utf-8').splitlines()
        extracted_data_list = extract_log_entries(log_entries, pattern)
        if not extracted_data_list:
            flash('No valid log entries found.')
            return redirect(url_for('upload_file'))

        return generate_csv_response(extracted_data_list, file.filename)

    except Exception as e:
        flash(f'Error processing file: {e}')
        return redirect(url_for('upload_file'))

def extract_log_entries(log_entries, pattern):
    extracted_data_list = []
    for log_entry in log_entries:
        match = pattern.match(log_entry.strip())
        if match:
            extracted_data_list.append(match.groupdict())
    return extracted_data_list

def generate_csv_response(extracted_data_list, original_filename):
    df = pd.DataFrame(extracted_data_list)
    output = BytesIO()
    df.to_csv(output, index=False, sep=';')
    output.seek(0)

    csv_filename = f"{original_filename.rsplit('.', 1)[0]}_extracted.csv"
    return send_file(output, mimetype='text/csv', download_name=csv_filename, as_attachment=True)

if __name__ == "__main__":
    from waitress import serve
    serve(app, host="0.0.0.0", port=5000)
