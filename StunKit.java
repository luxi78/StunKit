import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.SocketException;
import java.io.IOException;

class StunKit {
    private static final String STUN_SERVER_ADDRESS = "stun.meizu.com";
    private static final int STUN_SERVER_PORT = 3478;
    private static final int RECEIVE_TIMEOUT = 2;

    public enum NatType {
        BLOCKED, OPEN_INTERNET, FULL_CONE, SYMMETRIC_FIREWALL, RESTRICTED_CONE_NAT, RESTRICTED_PORT_NAT, SYMMETRIC_NAT;
    }
    public static class StunResult {
        public NatType natType;
        public String publicIp;
        public short publicPort;
    }

    public static StunResult makeStun(DatagramSocket socket) {
        if(!socket.isBound()) throw new RuntimeException("can not process a unbound datagram socket");
        StunResult result= null;
        int oldReceiveTimeout = 0;
        try {
            oldReceiveTimeout = socket.getSoTimeout();
            socket.setSoTimeout(RECEIVE_TIMEOUT);
        } catch (SocketException e) {
            e.printStackTrace();
        }

        //do test1
        ResponseResult stunResponse = stunTest(socket, null); 






        try {
            socket.setSoTimeout(oldReceiveTimeout);
        } catch( SocketException e) {
            e.printStackTrace();
        }
        return result;
    }

    private static class ResponseResult {
        public boolean responsed;
        public String externalIp;
        public int externalPort;
        public String sourceIp;
        public int sourcePort;
        public String changedIp;
        public int changedPort;
    }

    private static ResponseResult stunTest(DatagramSocket socket, byte[] msgData) {
        ResponseResult result = new ResponseResult();
        int msgLength = msgData==null? 0:msgData.length;
        MessageHeader header = new MessageHeader();
        header.generateTransactionID();
        header.setMessageLength(msgLength);
        header.setStunType(MessageHeader.StunType.BIND_REQUEST_MSG);
        byte[] headerData = header.encode();
        byte[] sendData = new byte[headerData.length + msgLength];
        System.arraycopy(headerData, 0, sendData, 0, headerData.length);
        if(msgLength > 0) System.arraycopy(msgData, 0, sendData, headerData.length, msgLength);
        
        boolean recvCorrect = false;
        while(!recvCorrect) {
            boolean received = false;
            int count = 3;
            while(!received) {
               try{
                   DatagramPacket  sendPacket = new DatagramPacket(
                       sendData, 
                       sendData.length, 
                       InetAddress.getByName(STUN_SERVER_ADDRESS), 
                       STUN_SERVER_PORT);
                   socket.send(sendPacket);
               } catch (Exception e) {
                   e.printStackTrace();
                   if(count > 0) {
                       count--;
                   } else {
                       result.responsed = false;
                        return result;
                   }
               }

            }
        }
        return null;
    }

    private static class UtilityException extends Exception {
        private static final long serialVersionUID = 3545800974716581680L;
        UtilityException(String mesg) { super(mesg); }
    }

    private static class MessageHeader {
        /*
         *  0                   1                   2                   3
         *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |      STUN Message Type        |         Message Length        |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *                          Transaction ID
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *                                                                 |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        private byte[] mStunType;// = new byte[2];
        private byte[] mMessageLength;// = new byte[2];
        private byte[] mTranId;// = new byte[16];

        public enum StunType {
           BIND_REQUEST_MSG(0x0001),
           BIND_RESPONSE_MSG(0X0101),
           BIND_ERROR_RESPONSE_MSG(0x0111),
           SHARED_SECRET_REQUEST_MSG(0x0002),
           SHARED_SECRET_RESPONSE_MSG(0X0102),
           SHARED_SECRETERROR_RESPONSE_MSG(0x0112);
           private final int value;
           private StunType(int value) {this.value = value;}
           public String toString() {return super.toString() + "value:" + value;}
           public int getValue() {return value;}
        }

        public  StunType getStunType(){
           try {
               int intType = Utility.twoBytesToInteger(mStunType);
               StunType[] types = StunType.values();
               for(StunType type : types) {
                   if(type.getValue() == intType) {
                       return type;
                   }
               }
           } catch (UtilityException e) {
               e.printStackTrace();
           }
           return null;
        }
        public void setStunType(StunType type) {
           try {
               mStunType = Utility.integerToTwoBytes(type.getValue());
           } catch (UtilityException e) {
               e.printStackTrace();
           }
        }

        public int getMessageLength() {
            try {
                return Utility.twoBytesToInteger(mMessageLength); 
            } catch(UtilityException e) {
                e.printStackTrace();
            }
            return -1;
        }

        public void setMessageLength(int length) {
            try {
                mMessageLength = Utility.integerToTwoBytes(length);
            } catch(UtilityException e) {
                e.printStackTrace();
            }
        }

        public void generateTransactionID() {
            mTranId = new byte[16];
            try  {
                System.arraycopy(Utility.integerToTwoBytes((int)(Math.random() * 65536)), 0, mTranId, 0, 2);
                System.arraycopy(Utility.integerToTwoBytes((int)(Math.random() * 65536)), 0, mTranId, 2, 2);
                System.arraycopy(Utility.integerToTwoBytes((int)(Math.random() * 65536)), 0, mTranId, 4, 2);
                System.arraycopy(Utility.integerToTwoBytes((int)(Math.random() * 65536)), 0, mTranId, 6, 2);
                System.arraycopy(Utility.integerToTwoBytes((int)(Math.random() * 65536)), 0, mTranId, 8, 2);
                System.arraycopy(Utility.integerToTwoBytes((int)(Math.random() * 65536)), 0, mTranId, 10, 2);
                System.arraycopy(Utility.integerToTwoBytes((int)(Math.random() * 65536)), 0, mTranId, 12, 2);
                System.arraycopy(Utility.integerToTwoBytes((int)(Math.random() * 65536)), 0, mTranId, 14, 2);
            } catch (UtilityException e) {
                e.printStackTrace();
            }
        }

        public byte[] getTransactionId() {
            return mTranId;
        }

        public boolean setTransactionId(byte[] tranId) {
            if(tranId.length != 16) return false;
            mTranId = tranId;
            return true;
        }

        public byte[] encode() {
            if(mStunType==null || mStunType.length!=2) throw new RuntimeException("Stuntype is not correct");
            if(mMessageLength ==null || mMessageLength.length!=2) throw new RuntimeException("mMessageLength is not correct");
            if(mTranId==null || mTranId.length!=16) throw new RuntimeException(" mTranId is not correct");

            byte[] result = new byte[20];
            System.arraycopy(mStunType, 0, result, 0, 2);
            System.arraycopy(mMessageLength, 0, result, 2, 2);
            System.arraycopy(mTranId, 0, result, 4, 16);
            return result;
        }
    }

    private static class Utility {
        public static final byte integerToOneByte(int value) throws UtilityException {
            if ((value > Math.pow(2,15)) || (value < 0)) {
                throw new UtilityException("Integer value " + value + " is larger than 2^15");
            }
            return (byte)(value & 0xFF);
        }

        public static final byte[] integerToTwoBytes(int value) throws UtilityException {
            byte[] result = new byte[2];
            if ((value > Math.pow(2,31)) || (value < 0)) {
                throw new UtilityException("Integer value " + value + " is larger than 2^31");
            }
            result[0] = (byte)((value >>> 8) & 0xFF);
            result[1] = (byte)(value & 0xFF);
            return result; 
        }

        public static final byte[] integerToFourBytes(int value) throws UtilityException {
            byte[] result = new byte[4];
            if ((value > Math.pow(2,63)) || (value < 0)) {
                throw new UtilityException("Integer value " + value + " is larger than 2^63");
            }
            result[0] = (byte)((value >>> 24) & 0xFF);
            result[1] = (byte)((value >>> 16) & 0xFF);
            result[2] = (byte)((value >>> 8) & 0xFF);
            result[3] = (byte)(value & 0xFF);
            return result; 
        }

        public static final int oneByteToInteger(byte value) throws UtilityException {
            return (int)value & 0xFF;
        }

        public static final int twoBytesToInteger(byte[] value) throws UtilityException {
            if (value.length < 2) {
                throw new UtilityException("Byte array too short!");
            }
            int temp0 = value[0] & 0xFF;
            int temp1 = value[1] & 0xFF;
            return ((temp0 << 8) + temp1);
        }

        public static final long fourBytesToLong(byte[] value) throws UtilityException {
            if (value.length < 4) {
                throw new UtilityException("Byte array too short!");
            }
            int temp0 = value[0] & 0xFF;
            int temp1 = value[1] & 0xFF;
            int temp2 = value[2] & 0xFF;
            int temp3 = value[3] & 0xFF;
            return (((long)temp0 << 24) + (temp1 << 16) + (temp2 << 8) + temp3);
        }	                                      
    }

    public static void main(String[] args) {
        System.out.println("aaa");
        DatagramSocket socket = null;
        try{
            socket = new DatagramSocket();
            StunResult stunResult = makeStun(socket);            
        } catch (Exception e ) {
            e.printStackTrace();
        }
    }
}
