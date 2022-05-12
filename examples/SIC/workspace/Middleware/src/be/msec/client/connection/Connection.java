/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package be.msec.client.connection;

import java.util.List;
import javax.smartcardio.*;


public class Connection implements IConnection {
	private int terminalNumber;
	private CardChannel c;
	private Card card;

	
	public Connection(){
		terminalNumber = 0;
	}
        public void setTerminal(int i){
            terminalNumber = i;
        }
        public static List<CardTerminal> listTerminals() throws CardException {
            TerminalFactory factory = TerminalFactory.getDefault();
            return factory.terminals().list();
        }
	public void connect() throws Exception {
            try{
                    TerminalFactory factory = TerminalFactory.getDefault();
                    List<CardTerminal> terminals = factory.terminals().list();
                    if(terminals.size()>terminalNumber){
                            card = terminals.get(terminalNumber).connect("*");
                            c = card.getBasicChannel();
                            
                    }else throw new Exception("Invalid terminal number given.");
            }catch(CardException ce){
                    throw new Exception("No readers found on the system.");
            }
	}
        public void close() throws Exception {
            if(card!=null)
		card.disconnect(true);
        }

	public ResponseAPDU transmit(CommandAPDU apdu) throws Exception {
            return c.transmit(apdu);
	}

}

