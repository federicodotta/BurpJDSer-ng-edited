package burp;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;

import java.awt.Component;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.GZIPInputStream;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private static PrintStream _stdout;
    private static PrintStream _stderr;

    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // get our out/err streams
        BurpExtender._stderr = new PrintStream(callbacks.getStderr());
        BurpExtender._stdout = new PrintStream(callbacks.getStdout());
        
        // set our extension name
        callbacks.setExtensionName("BurpJDSer-ng-edited");

        // register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(this);
        
        
    }

    //
    // implement IMessageEditorTabFactory
    //
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        // create a new instance of our custom editor tab
        return new SerializedJavaInputTab(controller, editable);
    }

    //
    // class implementing IMessageEditorTab
    //
    class SerializedJavaInputTab implements IMessageEditorTab {

        private boolean editable;
        private ITextEditor txtInput;
        private byte[] currentMessage;
        private byte[] serializeMagic = new byte[]{-84, -19};
        byte[] gzipMagic = {(byte)0x1f, (byte)0x8b};
        private Object obj;
        private byte[] crap;
        private XStream xstream = new XStream(new DomDriver());

        public SerializedJavaInputTab(IMessageEditorController controller, boolean editable) {
            
            this.editable = editable;

            // create an instance of Burp's text editor, to display our deserialized data
            txtInput = callbacks.createTextEditor();
            txtInput.setEditable(editable);
        }

        
        
        //
        // implement IMessageEditorTab
        //act
        @Override
        public String getTabCaption() {
            return "Deserialized Java";
        }

        @Override
        public Component getUiComponent() {
            return txtInput.getComponent();
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            // enable this tab for requests containing the serialized "magic" header
        	// Questo gli dice se i caratteri contenuti in serializeMagic (penso che siano "0xAC 0xED") sono presenti e quindi
        	// PROBABILMENTE e' un oggetto serializzato.
        	
        	// Se è una richiesta guardo se è un oggetto serializzato per abilitare la mia tab.
        	// Se è una risposta guardo se è un oggetto serializzato o gzippato
        	if(isRequest) {
        		return helpers.indexOf(content, serializeMagic, false, 0, content.length) > -1;
        	} else {
        		return ((helpers.indexOf(content, gzipMagic, false, 0, content.length) > -1) || (helpers.indexOf(content, serializeMagic, false, 0, content.length) > -1));
        	}
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            if (content == null) {
                // clear our display
                txtInput.setText(null);
                txtInput.setEditable(false);
            } else {
                ObjectInputStream is = null;
                try {
                	
                	byte[] baSer;
                	
                	// Se è un risposta ed è gzippata
                	if(!isRequest && helpers.indexOf(content, gzipMagic, false, 0, content.length) > -1) {
                		
                		
                		int msgBody = helpers.analyzeRequest(content).getBodyOffset();
                		int gzipPos = helpers.indexOf(content, gzipMagic, false, 0, content.length);
                		
                		
                		
                		byte[] baZipped = Arrays.copyOfRange(content, gzipPos, content.length);
                		
                		GZIPInputStream gzis = new GZIPInputStream(new ByteArrayInputStream(baZipped));
                		ByteArrayOutputStream baos = new ByteArrayOutputStream();
                		byte[] buffer = new byte[1024];
                		int bytes_read;
                		
                		while ((bytes_read = gzis.read(buffer)) > 0) {
            				baos.write(buffer, 0, bytes_read);
            			}
            			
            			byte[] baDecompressed = baos.toByteArray();
            			
            			int magicPos = helpers.indexOf(baDecompressed, serializeMagic, false, 0, baDecompressed.length);
                        baSer = Arrays.copyOfRange(baDecompressed, magicPos, baDecompressed.length);
                        
                        // Valutare se reinserire, ovviamente modificato
                        //crap = Arrays.copyOfRange(content, msgBody, gzipPos);
                		
                    // E' una richiesta O UNA RISPOSTA NO GZIPPATA (capita)    
                	} else {
                	

	                    // save offsets
	                    int magicPos = helpers.indexOf(content, serializeMagic, false, 0, content.length);
	                    int msgBody = helpers.analyzeRequest(content).getBodyOffset();
	
	                    // get serialized data
	                    baSer = Arrays.copyOfRange(content, magicPos, content.length);
	
	                    // save the crap buffer for reconstruction
	                    crap = Arrays.copyOfRange(content, msgBody, magicPos);
	                    
                	}

                    // deserialize the object
                    ByteArrayInputStream bais = new ByteArrayInputStream(baSer);

                    is = new ObjectInputStream(bais);
                    obj = is.readObject();
                    String xml = xstream.toXML(obj);

                    txtInput.setText(xml.getBytes());
                    
                } catch (IOException | ClassNotFoundException ex) {
                	
                    Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
                    txtInput.setText(helpers.stringToBytes("Something went wrong, did you change the body in a bad way?\n\n" + getStackTrace(ex)));
                
                } finally {
                    try {
                        is.close();
                    } catch (IOException ex) {
                        Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
                txtInput.setEditable(editable);
            }

            // remember the displayed content
            currentMessage = content;
        }

        @Override
        public byte[] getMessage() {
            // determine whether the user modified the deserialized data
            if (txtInput.isTextModified()) {
                // xstream doen't like newlines
                String xml = helpers.bytesToString(txtInput.getText()).replace("\n", "");
                // reserialize the data
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                try {
                    try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
                        oos.writeObject(xstream.fromXML(xml));
                        oos.flush();
                    }
                } catch (IOException ex) {
                    Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
                }
                // reconstruct our message (add the crap buffer)
                byte[] baObj = baos.toByteArray();
                byte[] newBody = new byte[baObj.length + crap.length];
                System.arraycopy(crap, 0, newBody, 0, crap.length);
                System.arraycopy(baObj, 0, newBody, crap.length, baObj.length);

                return helpers.buildHttpMessage(helpers.analyzeRequest(currentMessage).getHeaders(), newBody);
            } else {
                return currentMessage;
            }
        }

        @Override
        public boolean isModified() {
            return txtInput.isTextModified();
        }

        @Override
        public byte[] getSelectedData() {
            return txtInput.getSelectedText();
        }

        private String getStackTrace(Throwable t) {
            StringWriter stringWritter = new StringWriter();
            PrintWriter printWritter = new PrintWriter(stringWritter, true);
            t.printStackTrace(printWritter);
            printWritter.flush();
            stringWritter.flush();

            return stringWritter.toString();
        }
    }

}