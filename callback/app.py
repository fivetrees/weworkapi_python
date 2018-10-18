import tornado.web
import tornado.ioloop
from WXBizMsgCrypt import WXBizMsgCrypt
import sys
import xml.etree.cElementTree as ET
import xml.etree.ElementTree

class MainHandler(tornado.web.RequestHandler):

    def get(self):
        sToken = "L29xbwRgtizyOpOd9cs8oPXM5W2"
        sEncodingAESKey = "NfaRUX3KXZxz7mbF3fAPhJB5gLeRTmhEbEoDViPmf8q"
        sCorpID = "wweeae43b713dd2b06"
        wxcpt=WXBizMsgCrypt(sToken,sEncodingAESKey,sCorpID)

        sVerifyMsgSig=self.get_argument('msg_signature')
        sVerifyTimeStamp=self.get_argument('timestamp')
        sVerifyNonce=self.get_argument('nonce')
        sVerifyEchoStr=self.get_argument('echostr')

        ret,sEchoStr=wxcpt.VerifyURL(sVerifyMsgSig, sVerifyTimeStamp,sVerifyNonce,sVerifyEchoStr)
        if ret != 0:
            print "ERR: VerifyURL ret:" + ret
            sys.exit(1)

        self.write(sEchoStr)

    def post(self):
        sToken = "L29xbwRgtizyOpOd9cs8oPXM5W2"
        sEncodingAESKey = "NfaRUX3KXZxz7mbF3fAPhJB5gLeRTmhEbEoDViPmf8q"
        sCorpID = "wweeae43b713dd2b06"
        wxcpt = WXBizMsgCrypt(sToken, sEncodingAESKey, sCorpID)

        sVerifyMsgSig = self.get_argument('msg_signature')
        sVerifyTimeStamp = self.get_argument('timestamp')
        sVerifyNonce = self.get_argument('nonce')
        sReqData = self.request.body

        ret, sMsg = wxcpt.DecryptMsg(sReqData, sVerifyMsgSig, sVerifyTimeStamp, sVerifyNonce)
        if (ret != 0):
            print "ERR: VerifyURL ret:"
            sys.exit(1)

        xml_tree = ET.fromstring(sMsg)

        if xml.etree.ElementTree.iselement(xml_tree.find("Content")):
            content = xml_tree.find("Content").text
        elif xml.etree.ElementTree.iselement(xml_tree.find("EventKey")):
            content = xml_tree.find("EventKey").text
        else:
            content = "other type"

        user_id = xml_tree.find("FromUserName").text
        corp_id = xml_tree.find("ToUserName").text
        create_time = xml_tree.find("CreateTime").text

        content = "1.1.1.1\n2.2.2.2\n3.3.3.3"

        sRespData = """<xml>
                <ToUserName><![CDATA["""+user_id+"""]]></ToUserName>
                <FromUserName><![CDATA["""+corp_id+"""]]></FromUserName>
                <CreateTime>"""+create_time+"""</CreateTime>
                <MsgType><![CDATA[text]]></MsgType>
                <Content><![CDATA["""+content+"""]]></Content>
                </xml>"""

        ret,sEncryptMsg = wxcpt.EncryptMsg(sRespData, sVerifyNonce, sVerifyTimeStamp)
        if ret!=0:
            print "ERR: EncryptMsg ret: " + str(ret)
            sys.exit(1)

        self.write(sEncryptMsg)

application = tornado.web.Application([
    (r"/", MainHandler),
])

if __name__ == "__main__":

    try:
        application.listen(80)
        tornado.ioloop.IOLoop.instance().start()
    except KeyboardInterrupt as e:
        print("exit")
        exit(0)

