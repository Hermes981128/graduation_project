from flask import Flask, render_template, request
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
        item_dict["ID"] = item[0]
        item_dict["Time"] = item[1]
        item_dict["Source"] = item[2]
        item_dict["Destination"] = item[3]
        item_dict["Protocal"] = item[4]
        item_dict["Length"] = item[5]
        item_dict["Info"] = item[6]
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


if __name__ == '__main__':
    app.run(debug=True)
