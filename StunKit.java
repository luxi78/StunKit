import java.net.DatagramSocket;

class StunKit {
    public static class StunResult {
        public enum NatType {
            BLOCKED, OPEN_INTERNET, FULL_CONE, SYMMETRIC_FIREWALL, RESTRICTED_CONE_NAT, RESTRICTED_PORT_NAT, SYMMETRIC_NAT;
        }
    }
}
