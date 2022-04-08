from flask import Flask, render_template, request, Response
import os
import uuid

from tool.MysqlCommand import MysqlCommand
from tool.pars_pcap import PcapInstance

app = Flask(__name__)


@app.route('/source_data')
def source_data_page():
    return render_template('source_data.html')


@app.route('/api/source_data', methods=['POST'])
def source_data():
    page = request.json["page"]
    perPage = request.json["perPage"]
    db = MysqlCommand()
    filter, query = [], ""
    if request.json.get("Source", False): filter.append(f'''Source="{request.json['Source']}"''')
    if request.json.get("Destination", False): filter.append(f'''Destination="{request.json['Destination']}"''')
    if request.json.get("Protocal", False): filter.append(f'''Protocal={request.json['Protocal']}''')
    if len(filter) != 0: query = "WHERE " + " and ".join(filter)
    command = f'select ID,Time,Source,Destination,Protocal,Length,Info from graduation_design.source_data {query} ORDER BY ID DESC LIMIT {perPage} OFFSET {(page - 1) * perPage}'
    print(command)
    items = []
    for item in db.execute_with_return(command):
        item_dict = {}
        item_dict["ID"], item_dict["Time"], item_dict["Source"], item_dict["Destination"], item_dict["Protocal"], \
        item_dict["Length"], item_dict["Info"] = item
        items.append(item_dict)
    command = f'select COUNT(ID) from source_data {query}'
    total = db.execute_with_return(command)[0][0]
    return {"status": 0, "msg": "", "data": {"items": items, "total": total}}


@app.route('/analysis_pcap', methods=['GET', 'POST'])
def analysis_pcap_page():
    if request.method == 'GET':
        return render_template('analysis_pcap.html')
    elif request.method == 'POST':
        file_id = request.json["file_id"]
        if file_id == "": return {"status": 0, "msg": "", "data": {"items": []}}
        path = "static/receive_file/"
        filepath = path + file_id + ".pcap"
        items = []
        for Packet in PcapInstance(filepath):
            item = {}
            item["src"] = Packet.src
            item["sport"] = Packet.sport
            item["dst"] = Packet.dst
            item["dport"] = Packet.dport
            items.append(item)
        return {"status": 0, "msg": "", "data": {"items": items}}


@app.route('/api/receive_file', methods=['POST'])
def receive_file():
    path = "static/receive_file/"
    if not os.path.exists(path):
        os.mkdir(path)
    file = request.files.get('file')
    file_id = str(uuid.uuid1()).replace("-", "")
    filepath = path + file_id + ".pcap"
    file.save(filepath)
    return {"status": 0, "msg": "", "data": {"value": filepath, "ID": file_id}}


@app.route('/api/log', methods=['POST', 'GET'])
def analysis_log():
    """
    返回日志流
    :return:
    """
    if request.method == 'GET':
        return {"status": 0, "msg": "", "data": {"items": []}}
    elif request.method == 'POST':
        type = request.json.get('type', None)
        file_id = request.json.get('file_id')
        if type == 'training_model' and file_id != "":
            def generate():
                for i in range(99):
                    chunk = f'序号：{i}\n'
                    yield chunk

            return Response(generate(), content_type="application/octet-stream")
    return ''


@app.route('/test', methods=['GET'])
def test():
    """
    测试页面
    :return:
    """
    return render_template('test.html')


@app.route('/training_model', methods=['GET', 'POST'])
def training_model():
    """
    训练模型
    :return:
    """
    if request.method == 'GET':
        return render_template('training_model.html')
    elif request.method == 'POST':
        file_id = request.json["file_id"]
        if file_id == "": return {"status": 0, "msg": "", "data": {"items": []}}


if __name__ == '__main__':
    app.run(debug=True)
