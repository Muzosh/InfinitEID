/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package be.msec.client.connection;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author Jorn
 */


public interface IConnection {

        abstract void connect() throws Exception;
        abstract void close() throws Exception;
        
	abstract ResponseAPDU transmit(CommandAPDU apdu)  throws Exception;

}

