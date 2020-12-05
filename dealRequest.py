#!/usr/bin/python
# -*- coding:utf-8 -*-
# author : b1ng0

import time, random
import json, hashlib, requests
import hmac

from crypty_helper.xor import *
from crypty_helper.AES_use import *
from crypty_helper.DES_use import *
from crypty_helper.DES_3_use import *
from crypty_helper.RSA_sign import *
from gl import *


# 卫星第一次请求需要的所有数据
def getReqAuthData(options):
    timestamp = int(time.time())
    # Ru = random.randint(10000000000000000000000000000000, 99999999999999999999999999999999)
    # Ru 根据终端配置的随机数长度 生成的随机数
    Ru = getRandom(options)
    # 读取卫星信息
    with open("userInfo.json", "r") as userInfo:
        userInfo = json.load(userInfo)
    H = getHash(userInfo["userKey"] + str(Ru),options)
    H = xor_encrypt(userInfo["preRandom"], H)
    PIDu = xor_encrypt(str(userInfo["userId"]), H)
    MACu = getHash(userInfo["userId"] + str(Ru) +str(timestamp),options)
    ru = getHash(userInfo["userKey"] + userInfo['preRandom'],options)
    ru = xor_encrypt(str(Ru), ru)
    return json.dumps(
        {
            "Ts":str(timestamp),        # 时间戳；
            "Hs":H,                     # 哈希运算随机数H
            "PIDs":PIDu,                #卫星临时身份
            "MACs":MACu,                #卫星消息验证码
            "Rs":ru                     # 卫星每次更新后的随机数
        }
    )

def has_keys(dic, *keys):
    for k in keys:
        if k not in dic.keys():
            return False
    return True

def user_valid(userData):
    if has_keys(userData, 'Ru', 'MACu', 'Tu', 'Hu', 'PIDu'):
        if not is_timeout(userData['Tu']):
            return True
    return False

def  sendToNcc(satalliteData, userData):
    #将认证信息传递给ncc
    data = json.dumps({
        "ReqAuth":"ReqAuth",
        "userData":userData,
        "satalliteData":satalliteData
    })
    #  qi 卫星收到用户数据，连同自己数据一起发给NCC 真正延时和 4+2 S  认证延时2+2
    clear_and_add(data)
    # 读取卫星信息
    with open("userInfo.json", "r") as userInfo:
        userInfo = json.load(userInfo)
    url = "http://" + userInfo['ncc_ip'] + ":7543/identityCheck"
    # proxies = {'http': 'http://127.0.0.1:8080'}
    # reps = requests.post(url, data=data, proxies=proxies)
    reps = requests.post(url, data=data)
    auth_reps = json.loads(reps.content)
    # print auth_reps["MasterKey"]
    if auth_reps["Code"] == "0":
        # 通过auth_reps判断认证是否成功
        return dealResNcc(auth_reps, satalliteData["Rs"], userData["Ru"], userData["PIDu"], userData['Hu'], userData['Options'])
    else:
        raise Exception('ncc auth error')


# 处理Ncc返回信息
def dealResNcc(auth_reps, Rs, Ru, PIDu, Hu,options):
    timestamp = int(time.time())
    # 验证签名
    sign = auth_reps["Signiture"].decode('hex')
    verify = rsa_verify(sign, auth_reps["MasterKey"])
    if verify:
        # 读取卫星信息
        with open("userInfo.json", "r") as userInfo:
            userInfo = json.load(userInfo)
        masterKey = auth_reps["MasterKey"]
        # 生成sk, MAC_key
        # 面管理中心协商的密钥生成算法，计算出用于密钥更新的会话密钥 sk=h(h(K||r’||Rs)||K’)
        sk = getHash(masterKey + userInfo["userKey"],options)
        MAC_key = getHash(userInfo["userKey"] + masterKey + Rs,options)
        # 生成MAC
        msg = "ReqUserInfo" + str(timestamp) + PIDu + Hu
        MAC = getHmac(MAC_key, msg,options)
        # 请求用户身份信息
        url = "http://" + userInfo['ncc_ip'] + ":7543/reqUserInfo"
        data = {
            "ReqAuth":"ReqUserInfo",
            "Ts":str(timestamp),
            "PIDu":PIDu,
            "Hu": Hu,
            "MAC":str(MAC),    
        }
        # #  qi 卫星收到NCC返回数据 真正延时和 6+2 S  认证延时4+2
        clear_and_add(json.dumps(data))
        data["Options"]=options
        reps = requests.post(url, data=json.dumps(data))
        auth_reps = json.loads(reps.content)        
        #reps.text
        # print auth_reps
        # 返回信息：Esk{IDui，Ki}、MAC、TNCC
        return sendToUser(auth_reps, sk, MAC_key, Ru, PIDu,options)
    else:
        return {
            "ReqAuth":"500",
            "PIDu":PIDu
            }

# 处理卫星第二次返回的信息：Esk{IDu，Ku}、MAC、TNCC，并返回给用户
def sendToUser(auth_reps, sk, MAC_key, Ru, PIDu,options):
    # 从auth_reps中取出MAC, 用MAC_key进行验证
    # 先判断HMAC
    msg = auth_reps["AesIDu"] + auth_reps["AesKIu"] + auth_reps["Tncc"]
    MAC = auth_reps['HMAC']
    my_MAC = getHmac(MAC_key, msg,options)
    if MAC == my_MAC:
        IDu = decryptData(auth_reps['AesIDu'], sk,options)
        Ku = decryptData(auth_reps['AesKIu'], sk,options)
        # print "IDu:" + IDu, "Ku:" + Ku
        # 生成sessionId 并保存session
        # sessionId = random.randint(10000000000000000000000000000000, 99999999999999999999999999999999)   
        sessionId = str(getRandom(options))
        # 感觉对sessionId 少加密了一步 session_id=h(IDu||Ts’)
        # 读取卫星信息
        with open("userInfo.json", "r") as userInfo:
            userInfo = json.load(userInfo)
        # 生成 Ts
        timestamp = int(time.time())
        # qi
        # sessionId=getHash(IDu +str(timestamp))
        # 计算MAC_user_key, Hsat
        # 生成数据安全传输的密钥SK的元素  MACSAT_key  Hsat SessionId 唯一指定终端设备的标识消息
        # MACSAT_key=h(IDu||K||ru)
        MAC_user_key = getHash(IDu + Ku + Ru,options)
        # Hsat=h(K’||r’||r||Ts’)
        Hsat = getHash(userInfo["userKey"] + userInfo["preRandom"] + Ru + str(timestamp),options)
        # 将Eku(Hsat)，MAC发给用户
        # Ku_use = bytes(Ku.decode('hex'))
        # 对 Hsat 和sessionId 加密 用于数据传输
        secretHsat = encryptData(Hsat, Ku,options)
        secretSessionId = encryptData(str(sessionId), Ku,options)
        msg = "ReqUserSuccess" + secretHsat + secretSessionId
        MAC = getHmac(MAC_user_key, msg,options)
        data = {
            "ReqAuth":"200",
            "secretHsat":secretHsat,
            "sessionId":secretSessionId,
            "MAC":MAC,
            "PIDu":PIDu,
            "Ts":str(timestamp)
        }
        # 生成会话密钥 sessionKey sessionMACKey
        sessionKey = getHash(Hsat + Ku,options)
        sessionMACKey = getHash(IDu + Hsat,options)

        sessionDatas = {
            "IDu":IDu,
            "Ku":Ku,
            "sessionKey":sessionKey,
            "sessionMACKey":sessionMACKey,
            "time":int(time.time())
        }
        add_session(sessionId, sessionDatas)
        # 返回用户认证成功
        return data
    else:
        return {
            "ReqAuth":"500",
            "PIDu":PIDu
            }

# 获取用户的认证信息
def authResult(sessionId):
    return {
        "sessionId":sessionId,
        "sessionKey":sessions[sessionId]["sessionKey"],
        "MACKey":sessions[sessionId]["sessionMACKey"],
        "IDu":sessions[sessionId]["IDu"],
        "Ku":sessions[sessionId]["Ku"],
    }

# 向用户加密传输图片
def imgRepo(data, img_content, img_key, img_id,options):

    sessionId = data['sessionId']
    sessionKey = data['sessionKey']
    MACKey = bytes(data['MACKey'])
    
    # key_use = bytes(sessionKey.decode('hex'))
    # print  options
    content = encryptData(img_content, sessionKey,options)
    img_key = encryptData(img_key, sessionKey,options)
    MAC = getHmac(MACKey, content,options)

    # 传递给用户
    # url = "http://" + user_ip + ":8888/reqImg"
    conns_data = json.dumps({
        "ReqAuth": "rspImg",
        "sessionId": sessionId,
        "IDu": data['IDu'],
        "content":"img content",
        "imgId": img_id,
        "MAC":str(MAC)
    })
    clear_and_add(conns_data)
    data = json.dumps({
        "ReqAuth": "rspImg",
        "sessionId":sessionId,
        "content":content,
        "img_key":img_key,
        "MAC":str(MAC)
    })

    return data
    

# 处理二次认证
def dealSecondAuth(data):
    # 验证用户
    sessionId = data['sessionId']
    Ru = data['Ru']
    Tu = data['Tu']
    encode_data = data['encode_data']
    MACu = data['MAC']
    options=data["Options"]
    # 验证时间戳
    if is_timeout(Tu):
        raise Exception('timeout')

    session_data = authResult(sessionId)
    Ku = session_data['Ku']
    IDu = session_data['IDu']
    sessionKey = session_data['sessionKey']
    MACKey = session_data['MACKey']
    # clear_and_add
    add_conns = json.dumps({
        "ReqAuth": "second",
        "sessionId": sessionId,
        "Ru": Ru,
        "Tu": Tu,
        "encode_data": encode_data,
        "MAC": MACu,
        "IDu": IDu
    })
    # qi 卫星收到用户数据，并做初步判断 真正延时和 2+2 S 认证延时2
    clear_and_add(add_conns)
    # 验证MAC
    # 客户端加密方式 MAC_key = getHash(userInfo["userKey"] + userInfo["userId"]  + str(Ru))
    MAC_Key = bytes(getHash(Ku + IDu + Ru,options))
    msg = encode_data + Ru + Tu + sessionId
    if getHmac(MAC_Key, msg,options) != MACu:
        raise ValueError('MAC not compare.')
    # 比对信息
    compare_data = decryptData(encode_data, Ku,options)
    if compare_data != IDu + sessionKey + MACKey:
        raise ValueError('crypt data not compare.')
    
    # 生成二次认证需要的东西
    new_sessionId = str(getRandom(options))
    Rs = str(getRandom(options))
    Ts = int(time.time())
    # qi
    # new_sessionId=getHash(IDu +str(Ts))
    msg = Rs + str(Ts) + new_sessionId
    return_MAC = getHmac(MAC_Key, msg,options)

    # 更新sessions
    new_sessionKey = getHash(Ku + Ru + Rs + sessionKey,options)
    new_MACKey = getHash(IDu + Ku + Ru + MACKey,options)
    sessionDatas = {
        "IDu":IDu,
        "Ku":Ku,
        "sessionKey":new_sessionKey,
        "sessionMACKey":new_MACKey,
        "time":int(time.time())
    }
    add_session(new_sessionId, sessionDatas)

    return_data = json.dumps({
        "RepAuth": "rspSecondAuth",
        "Rs": Rs,
        "Ts": str(Ts),
        'sessionId': new_sessionId,
        "MAC": return_MAC,
        "IDu": IDu
    })
    # qi 卫星处理用户认证，生成新的数据密匙 真正延时和 4+2 S 认证延时2+2
    clear_and_add(return_data)
    return return_data
    
# 处理options['Len_Ru']
def getRandom(options):
    if options['Len_Ru'] == '1': # 16
        return random.randint(1000000000000000, 9999999999999999)
    elif options['Len_Ru'] == '2': # 32
        return random.randint(10000000000000000000000000000000, 99999999999999999999999999999999)
    elif options['Len_Ru'] == '3': # 48
        return random.randint(100000000000000000000000000000000000000000000000, 999999999999999999999999999999999999999999999999)

# 处理options['Hash_option']
def getHash(msg,options):
    if options['Hash_option'] == '1': # sha1
        return hashlib.sha1(msg).hexdigest()
    elif options['Hash_option'] == '2': # sha256
        return hashlib.sha256(msg).hexdigest()
    elif options['Hash_option'] == '3': # sha512
        return hashlib.sha512(msg).hexdigest()

# 处理hmac
def  getHmac(MAC_key, msg,options):
    if options['Hash_option'] == '1': # sha1
        return hmac.new(MAC_key, msg, hashlib.sha1).hexdigest()
    elif options['Hash_option'] == '2': # sha256
        return hmac.new(MAC_key, msg, hashlib.sha256).hexdigest()
    elif options['Hash_option'] == '3': # sha512
        return hmac.new(MAC_key, msg, hashlib.sha512).hexdigest()

# 处理options['Key_option']
def encryptData(data, key,options):
    if options['Key_option'] == '1': # AES
        return aes_encrypt(data, key)
    elif options['Key_option'] == '2': # DES
        return des_encrypt(data, key)
    elif options['Key_option'] == '3': # 3DES
        return three_des_encrypt(data, key)

def decryptData(data, key,options):
    if options['Key_option'] == '1': # AES
        return aes_decrypt(data, key)
    elif options['Key_option'] == '2': # DES
        return des_decrypt(data, key)
    elif options['Key_option'] == '3': # 3DES
        return three_des_decrypt(data, key)