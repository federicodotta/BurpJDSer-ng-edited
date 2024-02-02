package burp;

import com.thoughtworks.xstream.XStream;

import com.thoughtworks.xstream.converters.extended.NamedArrayConverter;
import com.thoughtworks.xstream.io.xml.DomDriver;
import com.thoughtworks.xstream.security.AnyTypePermission;

import java.awt.Component;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private static PrintStream _stdout;
    private static PrintStream _stderr;

    private static boolean printObjectsToStdout = true;


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
        private boolean isGzipped;
        private boolean isRequest;
        private XStream xstream = new XStream(new DomDriver());

        public SerializedJavaInputTab(IMessageEditorController controller, boolean editable) {

            this.editable = editable;

            // create an instance of Burp's text editor, to display our deserialized data
            txtInput = callbacks.createTextEditor();
            txtInput.setEditable(editable);

            xstream.addPermission(AnyTypePermission.ANY);

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

            if(isRequest) {
                //return helpers.indexOf(content, serializeMagic, false, 0, content.length) > -1;
                return ((helpers.indexOf(content, gzipMagic, false, 0, content.length) > -1) || (helpers.indexOf(content, serializeMagic, false, 0, content.length) > -1));
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

                    this.isRequest = isRequest;

                    // If the request/response is GZIPPED
                    if(helpers.indexOf(content, gzipMagic, false, 0, content.length) > -1) {

                        isGzipped = true;

                        int msgBody;
                        if(isRequest) {
                            msgBody = helpers.analyzeRequest(content).getBodyOffset();
                        } else {
                            msgBody = helpers.analyzeResponse(content).getBodyOffset();
                        }

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
                        crap = Arrays.copyOfRange(content, msgBody, gzipPos);

                    } else {

                        // Request/response not GZIPPED

                        isGzipped = false;

                        // save offsets
                        int magicPos = helpers.indexOf(content, serializeMagic, false, 0, content.length);
                        int msgBody;
                        if(isRequest) {
                            msgBody = helpers.analyzeRequest(content).getBodyOffset();
                        } else {
                            msgBody = helpers.analyzeResponse(content).getBodyOffset();
                        }

                        // get serialized data
                        baSer = Arrays.copyOfRange(content, magicPos, content.length);

                        // save the crap buffer for reconstruction
                        crap = Arrays.copyOfRange(content, msgBody, magicPos);

                    }

                    // deserialize the object
                    ByteArrayInputStream bais = new ByteArrayInputStream(baSer);

                    is = new ObjectInputStream(bais);
                    obj = is.readObject();

                    // Print object to stdout if enabled
                    if(printObjectsToStdout)
                        BurpExtender._stdout.println(toStringWithReflection(obj));

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

        public String toStringWithReflection(Object obj) {
            StringBuilder result = new StringBuilder();
            String newLine = System.getProperty("line.separator");

            result.append( obj.getClass().getName() );
            result.append( " Object {" );
            result.append(newLine);

            //determine fields declared in this class only (no fields of superclass)
            Field[] fields = obj.getClass().getDeclaredFields();

            //print field names paired with their values
            for ( Field field : fields  ) {
                result.append("  ");
                try {
                    result.append( field.getName() );
                    result.append(": ");
                    //requires access to private field:
                    result.append( field.get(obj) );
                } catch ( IllegalAccessException ex ) {
                    BurpExtender._stderr.println(ex);
                }
                result.append(newLine);
            }
            result.append("}");

            return result.toString();
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

                byte[] newBody;
                if(!isGzipped) {

                    newBody = new byte[baObj.length + crap.length];
                    System.arraycopy(crap, 0, newBody, 0, crap.length);
                    System.arraycopy(baObj, 0, newBody, crap.length, baObj.length);

                } else {

                    ByteArrayOutputStream bos = new ByteArrayOutputStream(baObj.length);

                    try {

                        GZIPOutputStream zipStream = new GZIPOutputStream(bos);

                        try {
                            zipStream.write(baObj);
                        }
                        finally {
                            zipStream.close();
                        }

                    } catch (Exception ex) {
                        Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
                        return currentMessage;

                    }
                    finally
                    {
                        try {
                            bos.close();
                        } catch (IOException ex) {
                            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
                            return currentMessage;
                        }
                    }

                    byte[] compressedData = bos.toByteArray();

                    newBody = new byte[compressedData.length + crap.length];
                    System.arraycopy(crap, 0, newBody, 0, crap.length);
                    System.arraycopy(compressedData, 0, newBody, crap.length, compressedData.length);

                }

                if(this.isRequest)
                    return helpers.buildHttpMessage(helpers.analyzeRequest(currentMessage).getHeaders(), newBody);
                else
                    return helpers.buildHttpMessage(helpers.analyzeResponse(currentMessage).getHeaders(), newBody);

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