<?php
session_start();

// Security Guard: Ensure the user is logged in
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true || !isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

// Ensure a CSRF token exists
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

require_once 'db.php';
$message = '';
$current_user_id = intval($_SESSION['user_id']);

// --- CREATE & UPDATE ACTIONS ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        header('HTTP/1.1 403 Forbidden');
        die("CSRF token validation failed.");
    }

    // 1. CREATE TASK
    if (isset($_POST['action']) && $_POST['action'] === 'create') {
        $title = isset($_POST['title']) ? trim($_POST['title']) : '';
        $description = isset($_POST['description']) ? trim($_POST['description']) : '';

        if (!empty($title)) {
            // Hardcode the current user's ID into the query for ownership isolation
            $stmt = $pdo->prepare("INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)");
            if ($stmt->execute([$current_user_id, $title, $description])) {
                $message = "Task added successfully.";
            }
        } else {
            $message = "Task title cannot be empty.";
        }
    }

    // 2. TOGGLE STATUS (UPDATE)
    if (isset($_POST['action']) && $_POST['action'] === 'toggle_status') {
        $task_id = intval($_POST['task_id']);
        $new_status = ($_POST['current_status'] === 'pending') ? 'completed' : 'pending';

        // Critical: The WHERE clause checks BOTH task ID and user ID so users cannot update someone else's task
        $stmt = $pdo->prepare("UPDATE tasks SET status = ? WHERE id = ? AND user_id = ?");
        if ($stmt->execute([$new_status, $task_id, $current_user_id])) {
            $message = "Task updated.";
        }
    }
}

// --- DELETE ACTION ---
if (isset($_GET['action']) && $_GET['action'] === 'delete' && isset($_GET['task_id'])) {
    
    if (!isset($_GET['token']) || !hash_equals($_SESSION['csrf_token'], $_GET['token'])) {
        header('HTTP/1.1 403 Forbidden');
        die("CSRF token validation failed.");
    }

    $task_id = intval($_GET['task_id']);

    // Critical: Ownership validation via SQL WHERE scope execution
    $stmt = $pdo->prepare("DELETE FROM tasks WHERE id = ? AND user_id = ?");
    if ($stmt->execute([$task_id, $current_user_id])) {
        $message = "Task deleted successfully.";
    }
}

// --- READ ACTION ---
// Isolate records so the user only pulls rows belonging to their specific account ID
$stmt = $pdo->prepare("SELECT id, title, description, status FROM tasks WHERE user_id = ? ORDER BY id DESC");
$stmt->execute([$current_user_id]);
$tasks = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>My Tasks</title>
</head>
<body>
    <h1>Welcome, <?php echo htmlspecialchars($_SESSION['username'] ?? 'User', ENT_QUOTES, 'UTF-8'); ?>!</h1>
    
    <!-- Navigation based on role architecture -->
    <nav>
        <a href="user.php">My Tasks</a>
        <?php if (isset($_SESSION['role']) && $_SESSION['role'] === 'admin'): ?>
            | <a href="admin.php" style="font-weight:bold; color:green;">Admin Dashboard</a>
        <?php endif; ?>
        | <a href="logout.php">Log Out</a>
    </nav>
    <hr>

    <?php if (!empty($message)): ?>
        <p style="color: blue; font-weight: bold;"><?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?></p>
    <?php endif; ?>

    <!-- CREATE FORM -->
    <h2>Add a New Task</h2>
    <form action="user.php" method="POST" style="margin-bottom: 30px;">
        <input type="hidden" name="action" value="create">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
        
        <p>
            <label>Task Title:<br>
            <input type="text" name="title" style="width: 300px;" required></label>
        </p>
        <p>
            <label>Description (Optional):<br>
            <textarea name="description" rows="3" style="width: 300px;"></textarea></label>
        </p>
        <button type="submit">Add Task</button>
    </form>

    <!-- READ & INTERACT TABLE -->
    <h2>My Active Workspace</h2>
    <table border="1" cellpadding="10" cellspacing="0" width="100%" style="max-width: 700px;">
        <thead>
            <tr>
                <th>Status</th>
                <th>Task Details</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php if (empty($tasks)): ?>
                <tr>
                    <td colspan="3" style="text-align: center; color: gray;">You haven't added any tasks yet!</td>
                </tr>
            <?php else: ?>
                <?php foreach ($tasks as $task): ?>
                    <tr style="<?php echo $task['status'] === 'completed' ? 'background-color: #f2f2f2; color: gray;' : ''; ?>">
                        <td width="15%" style="text-align: center;">
                            <!-- UPDATE STATUS FORM -->
                            <form action="user.php" method="POST">
                                <input type="hidden" name="action" value="toggle_status">
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                                <input type="hidden" name="task_id" value="<?php echo $task['id']; ?>">
                                <input type="hidden" name="current_status" value="<?php echo $task['status']; ?>">
                                
                                <button type="submit" style="cursor: pointer;">
                                    <?php echo $task['status'] === 'completed' ? '✅ Completed' : '⏳ Pending'; ?>
                                </button>
                            </form>
                        </td>
                        <td>
                            <strong style="<?php echo $task['status'] === 'completed' ? 'text-decoration: line-through;' : ''; ?>">
                                <?php echo htmlspecialchars($task['title'], ENT_QUOTES, 'UTF-8'); ?>
                            </strong>
                            <?php if (!empty($task['description'])): ?>
                                <p style="margin: 5px 0 0 0; font-size: 0.9em; color: #555;">
                                    <?php echo nl2br(htmlspecialchars($task['description'], ENT_QUOTES, 'UTF-8')); ?>
                                </p>
                            <?php endif; ?>
                        </td>
                        <td width="15%" style="text-align: center;">
                            <!-- SECURE DELETE LINK -->
                            <?php 
                            $deleteUrl = "user.php?action=delete&task_id=" . urlencode((string)$task['id']) . "&token=" . urlencode($_SESSION['csrf_token']);
                            ?>
                            <a href="<?php echo htmlspecialchars($deleteUrl, ENT_QUOTES, 'UTF-8'); ?>" 
                               onclick="return confirm('Are you sure you want to delete this task?');" 
                               style="color: red; text-decoration: none; font-weight: bold;">
                                [X] Remove
                            </a>
                        </td>
                    </tr>
                <?php endforeach; ?>
            <?php endif; ?>
        </tbody>
    </table>
</body>
</html>
