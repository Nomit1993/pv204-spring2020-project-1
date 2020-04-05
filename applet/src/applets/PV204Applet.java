package applets;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class PV204Applet extends javacard.framework.Applet {
    /**
     * Hidden constructor for the applet.
     *
     * The install method should be called instead.
     *
     * @param parameters Array of configuration parameters for the applet.
     * @param offset Starting offset in the parameters array.
     * @param length Length of data in the parameters array.
     */
    protected PV204Applet(byte[] parameters, short offset, byte length) {
        // TODO: Parse the supplied parameters.
        // TODO: Set up and initialize variables for internal use.

        // Register this applet instance via JavaCard.
        register();
    }

    /**
     * Clear sensitive data from memory.
     *
     * Clear session keys, ephemeral keys, etc. that we do not wish others after us
     * to know.
     */
    protected void clearData() {
        // TODO: Clear sensitive data. Overwrite with zeros or random bytes.
    }

    /**
     * Check if applet can be selected for use at the moment.
     *
     * Called by the card upon deselecting the applet. This also clear any sensitive
     * data that might remain the memory.
     */
    @Override
    public void deselect() {
        clearData();
    }

    /**
     * Install the applet with the given parameters.
     *
     * @param parameters Array of configuration parameters for the applet.
     * @param offset Starting offset in the parameters array.
     * @param length Length of data in the parameters array.
     */
    public static void install(byte[] parameters, short offset, byte length)
        throws ISOException
    {
        // NOTE: Return value is ignored. All the necessary configuration happens in
        // the constructor.
        new PV204Applet(parameters, offset, length);
    }

    /**
     * Process an incoming APDU.
     *
     * @param apdu The APDU to be processed.
     */
    @Override
    public void process(APDU apdu) throws ISOException {
    }

    /**
     * Check if applet can be selected for use at the moment.
     *
     * Called by the card to check before selecting the applet. This also clear any
     * sensitive data that might remain the memory.
     *
     * @return true if applet can be selected; false otherwise.
     */
    @Override
    public boolean select() {
        clearData();

        return true;
    }
}
