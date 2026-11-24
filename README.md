# nginx-log-analyzer
Nginx访问日志可视化分析工具

## 项目介绍
基于Python Flask + ECharts开发的Nginx日志分析工具。
上传Nginx日志文件后自动解析，生成可视化图表：
- 访问量趋势图
- 访问IP Top10柱状图
- 访问URL Top10柱状图
- 状态码分布饼图
识别高危访问记录，支持导出异常记录CSV。

## 环境依赖
Python3
Flask

安装依赖：
```bash
pip install flask

运行方法
 
bash
  
cd nginx-log-analyzer
python app.py
 
 
打开浏览器访问：http://127.0.0.1:5000
选择sample.log上传解析，查看可视化结果。
 
目录结构
 
plaintext
  
nginx-log-analyzer/
├── app.py
├── sample.log
├── static/
│   └── js/echarts.min.js
├── templates/
│   └── index.html
└── README.md