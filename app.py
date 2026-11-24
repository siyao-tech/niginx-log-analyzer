from flask import Flask, render_template, request, Response
import re
from collections import Counter
import csv
from io import StringIO

app = Flask(__name__)

# Nginx日志正则
pattern = re.compile(r'(?P<ip>[\d.]+) - - \[(?P<time>[^\]]+)\] "(?P<method>\w+) (?P<url>[^ ]+) [^"]+" (?P<status>\d+) \d+ "(?P<ua>[^"]+)"')
# 异常规则
risk_keywords = ["../", "passwd", "admin", "scanner", "curl"]

def parse_log(file):
    lines = file.read().decode("utf-8").splitlines()
    records = []
    anomaly = []
    time_list = []
    ip_list = []
    url_list = []
    status_list = []
    for line in lines:
        m = pattern.search(line)
        if not m:
            continue
        d = m.groupdict()
        records.append(d)
        time_list.append(d["time"].split(":")[0])
        ip_list.append(d["ip"])
        url_list.append(d["url"])
        status_list.append(d["status"])
        # 判断异常
        for kw in risk_keywords:
            if kw in d["url"] or kw in d["ua"]:
                anomaly.append({**d, "reason": "存在风险访问"})
                break
    trend = Counter(time_list)
    ip_cnt = Counter(ip_list).most_common(10)
    url_cnt = Counter(url_list).most_common(10)
    status_cnt = Counter(status_list)
    return trend, ip_cnt, url_cnt, status_cnt, anomaly

@app.route("/", methods=["GET","POST"])
def index():
    trend = {}
    ip_cnt = []
    url_cnt = []
    status_cnt = {}
    anomaly = []
    if request.method == "POST":
        f = request.files.get("logfile")
        if f:
            trend, ip_cnt, url_cnt, status_cnt, anomaly = parse_log(f)
    return render_template("index.html", trend=trend, ip_cnt=ip_cnt, url_cnt=url_cnt, status_cnt=status_cnt, anomaly=anomaly)

@app.route("/export")
def export():
    si = StringIO()
    w = csv.writer(si)
    w.writerow(["IP","时间","方法","URL","状态码","UA","异常原因"])
    for row in anomaly:
        w.writerow([row["ip"],row["time"],row["method"],row["url"],row["status"],row["ua"],row["reason"]])
    output = Response(si.getvalue(), mimetype="text/csv")
    output.headers["Content-Disposition"] = "attachment; filename=anomaly.csv"
    return output

if __name__ == "__main__":
    app.run(debug=True)