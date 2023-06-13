package test001;
import javafx.application.Application;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import java.io.*;
import java.net.HttpURLConnection;
import java.util.HashMap;
import java.util.Map;
import java.net.URI;
import java.net.URL;
import com.google.gson.*;
public class chatbot extends Application {
	private String api;
	private String uri="https://api.qingyunke.com/api.php?key=free&appid=0&msg=%s";

    private static final String USER_FILE = "users.pkl";
    private Map<String, String> users;

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) {
        // Load user data from file
        loadUsers();

        // Create UI elements
        Label usernameLabel = new Label("用户名:");
        TextField usernameField = new TextField();
        Label passwordLabel = new Label("密码:");
        PasswordField passwordField = new PasswordField();
        Button loginButton = new Button("登录");
        Button registerButton = new Button("注册");

        // Set event handlers
        loginButton.setOnAction(event -> {
            String username = usernameField.getText();
            String password = passwordField.getText();
            if (login(username, password)) {
                showAlert("登陆成功");
                primaryStage.close();
                openMainWindow(username);
                
            } else {
                showAlert("用户名或密码错误");
            }
        });

        registerButton.setOnAction(event -> openRegisterWindow());

        // Create layout
        VBox vbox = new VBox(10);
        vbox.setPadding(new Insets(10));
        vbox.getChildren().addAll(usernameLabel, usernameField, passwordLabel, passwordField, loginButton, registerButton);

        // Create scene
        Scene scene = new Scene(vbox, 400, 300);

        // Set up stage
        primaryStage.setTitle("用户登录");
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void loadUsers() {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(USER_FILE))) {
            users = (Map<String, String>) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            // If file doesn't exist or error reading file, initialize an empty users map
            users = new HashMap<>();
        }
    }

    private void saveUsers() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(USER_FILE))) {
            oos.writeObject(users);
        } catch (IOException e) {
            e.printStackTrace();
            showAlert("保存用户信息失败");
        }
    }

    private boolean register(String username, String password) {
        if (users.containsKey(username)) {
            return false; // 用户名已经存在
        }

        users.put(username, password);
        saveUsers();
        return true;
    }

    private boolean login(String username, String password) {
        String storedPassword = users.get(username);
        return storedPassword != null && storedPassword.equals(password);
    }

    private void showAlert(String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("Information");
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    private void openRegisterWindow() {
        Stage registerStage = new Stage();
        Label usernamedValidationLabel = new Label("用户名需要以大写字母开头，至少六位");
        Label passwordValidationLabel = new Label("密码需要包含大写字母，数字，符号");
        Label usernameLabel = new Label("Username:");
        TextField usernameField = new TextField();
        Label passwordLabel = new Label("Password:");
        PasswordField passwordField = new PasswordField();
        Label confirmPasswordLabel = new Label("Confirm Password:");
        PasswordField confirmPasswordField = new PasswordField();
        Button registerButton = new Button("Register");

        registerButton.setOnAction(event -> {
            String username = usernameField.getText();
            String password = passwordField.getText();
            // 验证用户名是否符合规则
            if (!username.matches("^\\p{Lu}.*") || username.length() < 6) {
                showAlert("用户名不合法");
                return;
            }
            // 验证密码是否符合规则
            if (!password.matches(".*[0-9].*") || !password.matches(".*\\p{Lu}.*") || !password.matches(".*[!@#$%^&*].*")) {
                showAlert("密码不合法");
                return;
            }
            String confirmPassword = confirmPasswordField.getText();
            if (password.equals(confirmPassword)) {
                if (register(username, password)) {
                    showAlert("注册成功");
                    registerStage.close();
                } else {
                    showAlert("用户已经存在");
                }
            } else {
                showAlert("输入的密码不一致");
            }
        });

        VBox vbox = new VBox(10);
        vbox.setPadding(new Insets(10));
        vbox.getChildren().addAll(usernameLabel, usernameField, passwordLabel, passwordField,
                confirmPasswordLabel, confirmPasswordField,usernamedValidationLabel,passwordValidationLabel, registerButton);

        Scene scene = new Scene(vbox, 400, 300);

        registerStage.setTitle("用户注册");
        registerStage.setScene(scene);
        registerStage.show();
    }

    private void openMainWindow(String username) {
    	Bot bot=new Bot();
        Stage mainStage = new Stage();
        // UI elements
        TextArea chatArea = new TextArea();
        TextField inputField = new TextField();
        Button sendButton = new Button("Send");
        // Set event handler for send button
        sendButton.setOnAction(event -> {
            String message = inputField.getText();
            String sender = username;
            String replySender = "聊天机器人小i";
            String reply = bot.sendChatbotRequest(message);
            // Add message to chat area
            chatArea.appendText(sender + ": " + message + "\n");
            chatArea.appendText(replySender + ": " + reply + "\n");
            // Clear input field
            inputField.clear();
        });
        // Create layout
        VBox vbox = new VBox(10);
        vbox.setPadding(new Insets(10));
        vbox.getChildren().addAll(chatArea, inputField, sendButton);
        // Create scene
        Scene scene = new Scene(vbox, 400, 300);

        mainStage.setTitle("Chat Window");
        mainStage.setScene(scene);
        mainStage.show();}
        
public class Bot {
    private String sendChatbotRequest(String message) {
        try {
            // Set API URL
            String apiUrl = "http://api.qingyunke.com/api.php?key=free&appid=0&msg=" + message; // Replace with the actual API URL
            // Create URI object
            URI uri = new URI(apiUrl);
            // Create URL object from URI
            URL url = uri.toURL();
            // Rest of your code..
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            // Set request method
            connection.setRequestMethod("GET");
            // Get response code
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                // Read response
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();
                Gson gson = new Gson();
                JsonObject jsonObject = gson.fromJson(response.toString(), JsonObject.class);
                // 获取 "content" 字段的值
                String content = jsonObject.get("content").getAsString();
                return content;
            } else {
                return "Error: Failed to connect to the chatbot API.";
            }
        } catch (Exception e) {
            e.printStackTrace();
            return "Error: Failed to connect to the chatbot API.";
        }
    }
}
}
     
