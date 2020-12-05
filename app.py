# -*- coding:utf-8 -*-
# from threading import Event
import eventlet
eventlet.monkey_patch()
from flask import Flask, request, Response
from flask_socketio import SocketIO
from flask_cors import CORS
import json
from threading import RLock

from dealRequest import *
from gl import *
from imgCompress import imgCompress
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
CORS(app, supports_credentials=True)

thread_lock = RLock()
socketio = SocketIO(app)
with open("log.txt", "r+") as f:
    f.truncate()

with open("log.txt", "r+") as f:
            f.truncate()

@app.route('/')
def index():
    return app.send_static_file('display/index.html')

@app.route('/show')
def show():
    return app.send_static_file('show.html')

@socketio.on('connect', namespace='/test_conn')
def test_connect():
     socketio.start_background_task(target=background_thread)

def background_thread():
    eventlet.spawn_n(gtask_socketio_emit)

def gtask_socketio_emit():
    while True:
        with thread_lock:
            socketio.emit('server_response', {'data': conns},namespace='/test_conn') 
            conns[:]=[]
        eventlet.sleep(3)
 
# 用户请求卫星图片
@app.route('/reqImg', methods=['GET', 'POST'])
def reqImg():
    if(request.data):
        request_data = json.loads(request.data)
        sessionId = request_data["sessionId"]

        imgId = request_data["imgId"] # 图片1/2/3
        ratioId = request_data['ratioId'] # 分辨率 1/2/3 低/中/高

        options={"Key_option":str(request_data["Options"]['Key_option']),'Hash_option':str(request_data["Options"]['Hash_option'])}
     
        try:
            session_data = sessions[sessionId]
            # 判断session是否过期
            now = int(time.time())
            if now-session_data['time'] > 60*30:
                return "expire", 401

            IDu = session_data['IDu']
            userData = json.dumps({
                'IDu': IDu,
                'sessionId': sessionId,
                'ReqAuth': 'reqImg',
                'ratioId': ratioId,
                'imgId': imgId
            })
            clear_and_add(userData)
        except KeyError:
            return 'you not auth success', 500
         # encode img
        if imgCompress.img_encode(imgId,ratioId) == 1:
            return 'img encode error', 500
        # part.j2k lena.key ==> user
        with open("imgCompress/transcoding/transcoding/Client/part.j2k", "rb") as img:
            img_content = img.read()
        with open("imgCompress/transcoding/transcoding/Client/lena.key", "rb") as key:
            img_key = key.read()
    
        # 对图像信息进行加密
        if img_content and img_key:
            try:
                data = authResult(sessionId)
                
                return imgRepo(data, img_content,img_key, imgId,options)
            except Exception, e:
                print e
                imgError = json.dumps({
                    'error': e,
                    'ReqAuth': 'imgError',
                    'IDu': IDu
                })
                clear_and_add(imgError)
                return "img crypty error", 500

    return "method error", 500


# 认证成功访问页面
@app.route('/success', methods=['GET', 'POST'])
def success():
    # if request.method == 'POST':
    if(request.data):
        try:
            sessionId = json.loads(request.data)["sessionId"]
            session_data = sessions[str(sessionId)]
            # 判断session是否过期
            now = int(time.time())
            if now-session_data['time'] < 60*30:
                return '200'
            # qi
            # else:  
            #     del_session(sessionId)

            return "expire", 401
        except Exception, e:
            print e
            return "500", 500

    return "500", 500


# 卫星收到用户发来的认证信息，连同自己的认证信息一起发给ncc
@app.route('/reqAuth', methods=['GET', 'POST'])
def reqAuthFromUser():
    # 这里要对用户信息做出判断
    if(request.data):
        userData = json.loads(request.data)
        # 粗糙的验证用户信息
        if not user_valid(userData):
            return 'timeout', 500
        # 统计接入用户
        global conn_user
        global succ_user
        # 奇 
        global storage
        conn_user += 1
        userData['conn_user'] = conn_user
        userData['succ_user'] = succ_user
        clear_and_add(json.dumps(userData))
        try:
            options = userData['Options']
        except Exception, e:
            print "no options from user"
            pass
        # 获取卫星认证数据
        satalliteData = getReqAuthData( userData['Options'])
        satalliteData = json.loads(satalliteData)
        # sendToNcc
        try:
            # sendToNcc会延时4S
            data = sendToNcc(satalliteData, userData)
            # 统计成功信息
            succ_user += 1
            data['conn_user'] = conn_user
            data['succ_user'] = succ_user
            data['storage'] = get_sessions_storage()
            #  qi 卫星收到用户数据，并做初步判断 真正延时和 8+2 S  认证延时6+2
            clear_and_add(json.dumps(data))
            return data
        except Exception, e:
            print e
            data = json.dumps({
                "ReqAuth":"500",
                "PIDu":userData["PIDu"],
                "conn_user": conn_user,
                "succ_user": succ_user,
                "storage" :get_sessions_storage()
                })
            clear_and_add(data)
            return Response(status=500, response=data)
    else:
        return Response(status=500)

# 二次认证
@app.route('/secondAuth', methods=['GET', 'POST'])
def secondAuth():
    # 接收认证数据
    if request.data:
        try:
            data = json.loads(request.data)
            # dealSecondAuth 休眠4秒时间
            return dealSecondAuth(data)
        except Exception, e:
            print e
            data = json.dumps({
                "RepAuth":"500",
                })
            clear_and_add(data)
            return 'auth error', 500
    else:
        return 'method error', 500

@app.route('/getUserList', methods=['GET', 'POST'])
def getUserList():
    return json.dumps(sessions)


if __name__ == "__main__":
    socketio.run(
        app,
        debug=True,
        host='127.0.0.1',
        port=2333,
        )