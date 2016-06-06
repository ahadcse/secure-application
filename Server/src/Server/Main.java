package Server;

import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Main {

    public static void main(String[] args) {
        try {
            ServerSocket ss;
            Socket sc = null;
            ss = new ServerSocket(4141);

            while(true) {
                sc = ss.accept();
                //Server server = new Server(sc);
                ServerClass server = new ServerClass(sc);
                Thread t = new Thread(server);
                t.start();
                //ServerThread st = new ServerThread(sc);
                //st.start();
            }

        } catch (UnknownHostException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

}
