<?php
session_start();

// Check if user is logged in and is admin
if (!isset($_SESSION['admin_id']) || !isset($_SESSION['is_admin']) || $_SESSION['is_admin'] != 1) {
    header("Location: admin_login.php");
    exit();
}

// Custom error handler to log errors and display a user-friendly message
function customErrorHandler($errno, $errstr, $errfile, $errline) {
    $logEntry = sprintf("[%s] Error: [%d] %s on line %d in %s\n", date("Y-m-d H:i:s"), $errno, $errstr, $errline, $errfile);
    error_log($logEntry, 3, "error_log.txt");
    if ($errno == E_USER_ERROR) {
        echo "<div class='alert alert-danger'><i class='fas fa-exclamation-circle'></i> A critical error occurred. Please try again later.</div>";
        exit();
    }
    return true;
}
set_error_handler("customErrorHandler");

// Database connection settings removed; using external db file instead
require_once 'database.php';

// Sanitize user input
function sanitizeInput($data) {
    return htmlspecialchars(strip_tags(trim($data)));
}

// Generate CSRF token if it doesn't exist
function generateOrValidateToken() {
    if (empty($_SESSION['token'])) {
        $_SESSION['token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['token'];
}

// Validate CSRF token
function validateToken($token) {
    return isset($_SESSION['token']) && hash_equals($_SESSION['token'], $token);
}

// Fetch subjects for enrollment
$all_subjects = [];
$result = $conn->query("SELECT subject_id, subject_name FROM subjects");
if ($result) {
    while ($subject = $result->fetch_assoc()) {
        $all_subjects[] = $subject;
    }
}

// Add these new queries after the existing database queries
$dashboard_stats = [
    'total_students' => $conn->query("SELECT COUNT(*) as count FROM students")->fetch_assoc()['count'],
    'total_teachers' => $conn->query("SELECT COUNT(*) as count FROM teachers")->fetch_assoc()['count'],
    'total_subjects' => $conn->query("SELECT COUNT(*) as count FROM subjects")->fetch_assoc()['count'],
    'pending_leaves' => $conn->query("SELECT COUNT(*) as count FROM leave_requests WHERE status='pending'")->fetch_assoc()['count'],
    'attendance_today' => $conn->query("SELECT COUNT(*) as count FROM attendance WHERE class_date = CURDATE()")->fetch_assoc()['count']
];

// Add after the existing chart data
$attendance_stats = $conn->query("
    SELECT status, COUNT(*) as count 
    FROM attendance 
    WHERE class_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
    GROUP BY status
");

// Add this query after the existing attendance query
$attendance_with_details = $conn->query("
    SELECT a.*, s.name as student_name, sub.subject_name 
    FROM attendance a
    JOIN students s ON a.student_id = s.student_id
    JOIN subjects sub ON a.subject_id = sub.subject_id
    ORDER BY a.class_date DESC, a.subject_id
");

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token for every POST submission
    if (!isset($_POST['token']) || !validateToken($_POST['token'])) {
        $_SESSION['message'] = "Invalid security token! Please try again.";
        header("Location: " . $_SERVER['PHP_SELF']);
        exit();
    }
    // Regenerate token for one-time use
    $_SESSION['token'] = bin2hex(random_bytes(32));

    // Update Leave Request (Admin Action)
    if (isset($_POST['update_leave_request'])) {
      $request_id    = $conn->real_escape_string(sanitizeInput($_POST['request_id']));
      $new_status    = $conn->real_escape_string(sanitizeInput($_POST['status']));
      $denied_reason = "";
      if ($new_status === 'denied') {
        $denied_reason = $conn->real_escape_string(sanitizeInput($_POST['denied_reason']));
      }
      $sql = $conn->prepare("UPDATE leave_requests SET status = ?, denied_reason = ? WHERE id = ?");
      $sql->bind_param("ssi", $new_status, $denied_reason, $request_id);
      if ($sql->execute()) {
        $_SESSION['message'] = "Leave request updated successfully!";
      } else {
        $_SESSION['message'] = "Error updating leave request: " . $sql->error;
      }
    }

    // Delete Leave Request (Admin Action)
    if (isset($_POST['delete_leave_request'])) {
      $request_id = $conn->real_escape_string(sanitizeInput($_POST['request_id']));
      $sql = $conn->prepare("DELETE FROM leave_requests WHERE id = ?");
      $sql->bind_param("i", $request_id);
      if ($sql->execute()) {
        $_SESSION['message'] = "Leave request deleted successfully!";
      } else {
        $_SESSION['message'] = "Error deleting leave request: " . $sql->error;
      }
    }

    // Add Attendance for multiple student IDs
    if (isset($_POST['add_attendance'])) {
        $student_ids_raw = $conn->real_escape_string(sanitizeInput($_POST['student_ids']));
        $subject_id      = $conn->real_escape_string(sanitizeInput($_POST['subject_id']));
        $class_date      = $conn->real_escape_string(sanitizeInput($_POST['class_date']));
        $week_number     = $conn->real_escape_string(sanitizeInput($_POST['week_number']));
        $status          = $conn->real_escape_string(sanitizeInput($_POST['status']));
        $prefix          = "csc-24f-";
        
        $student_ids = explode(",", $student_ids_raw);
        foreach ($student_ids as $id) {
            $id = trim($id);
            if (strlen($id) === 3) {
                $id = $prefix . $id;
            }
            $sql = $conn->prepare("INSERT INTO attendance (student_id, subject_id, class_date, week_number, status) VALUES (?, ?, ?, ?, ?)");
            $sql->bind_param("sssis", $id, $subject_id, $class_date, $week_number, $status);
            if (!$sql->execute()) {
                $_SESSION['message'] = "Error adding attendance: " . $sql->error;
                break;
            } else {
                $_SESSION['message'] = "Attendance added successfully!";
            }
        }
    }

    // Delete Attendance
    if (isset($_POST['delete_attendance'])) {
        $id = $conn->real_escape_string(sanitizeInput($_POST['id']));
        $sql = $conn->prepare("DELETE FROM attendance WHERE id = ?");
        $sql->bind_param("i", $id);
        if ($sql->execute()) {
            $_SESSION['message'] = "Attendance record deleted!";
        } else {
            $_SESSION['message'] = "Error deleting attendance: " . $sql->error;
        }
    }

    // Add Student
    if (isset($_POST['add_student'])) {
        $student_id = $conn->real_escape_string(sanitizeInput($_POST['student_id']));
        $name       = $conn->real_escape_string(sanitizeInput($_POST['name']));
        $email      = $conn->real_escape_string(sanitizeInput($_POST['email']));
        $stream     = $conn->real_escape_string(sanitizeInput($_POST['medical_or_preenj']));
        $password   = password_hash(sanitizeInput($_POST['password']), PASSWORD_DEFAULT);

        $sql = $conn->prepare("INSERT INTO students (student_id, name, email, medical_or_preenj, password) VALUES (?, ?, ?, ?, ?)");
        $sql->bind_param("sssss", $student_id, $name, $email, $stream, $password);
        if ($sql->execute()) {
            $_SESSION['message'] = "Student added successfully!";
        } else {
            $_SESSION['message'] = "Error adding student: " . $sql->error;
        }
    }

    // Delete Student
    if (isset($_POST['delete_student'])) {
        $student_id = $conn->real_escape_string(sanitizeInput($_POST['student_id']));
        $sql = $conn->prepare("DELETE FROM students WHERE student_id = ?");
        $sql->bind_param("s", $student_id);
        if ($sql->execute()) {
            $_SESSION['message'] = "Student deleted!";
        } else {
            $_SESSION['message'] = "Error deleting student: " . $sql->error;
        }
    }

    // Update Student Details (new feature)
    if (isset($_POST['update_student'])) {
        $student_id = $conn->real_escape_string(sanitizeInput($_POST['student_id']));
        $name       = $conn->real_escape_string(sanitizeInput($_POST['name']));
        $email      = $conn->real_escape_string(sanitizeInput($_POST['email']));
        $stream     = $conn->real_escape_string(sanitizeInput($_POST['medical_or_preenj']));
        $sql = $conn->prepare("UPDATE students SET name = ?, email = ?, medical_or_preenj = ? WHERE student_id = ?");
        $sql->bind_param("ssss", $name, $email, $stream, $student_id);
        if ($sql->execute()) {
            $_SESSION['message'] = "Student updated successfully!";
        } else {
            $_SESSION['message'] = "Error updating student: " . $sql->error;
        }
    }

    // Delete Teacher Assignment
    if (isset($_POST['delete_teacher_assignment'])) {
        $id = $conn->real_escape_string(sanitizeInput($_POST['id']));
        $sql = $conn->prepare("DELETE FROM teacher_assignments WHERE id = ?");
        $sql->bind_param("i", $id);
        if ($sql->execute()) {
            $_SESSION['message'] = "Teacher assignment deleted!";
        } else {
            $_SESSION['message'] = "Error deleting teacher assignment: " . $sql->error;
        }
    }

    // Delete Student Enrollment
    if (isset($_POST['delete_student_enrollment'])) {
        $id = $conn->real_escape_string(sanitizeInput($_POST['id']));
        $sql = $conn->prepare("DELETE FROM student_enrollment WHERE id = ?");
        $sql->bind_param("i", $id);
        if ($sql->execute()) {
            $_SESSION['message'] = "Student enrollment removed!";
        } else {
            $_SESSION['message'] = "Error deleting enrollment: " . $sql->error;
        }
    }

    // Delete Admin
    if (isset($_POST['delete_admin'])) {
        $admin_id = $conn->real_escape_string(sanitizeInput($_POST['admin_id']));
        $sql = $conn->prepare("DELETE FROM admins WHERE admin_id = ?");
        $sql->bind_param("i", $admin_id);
        if ($sql->execute()) {
            $_SESSION['message'] = "Admin account deleted!";
        } else {
            $_SESSION['message'] = "Error deleting admin: " . $sql->error;
        }
    }

    // Add Student Enrollment for multiple subjects with added student existence check
    if (isset($_POST['add_student_enrollment'])) {
        $student_id = $conn->real_escape_string(sanitizeInput($_POST['student_id']));
        // Check if student exists
        $checkStudent = $conn->prepare("SELECT COUNT(*) FROM students WHERE student_id = ?");
        $checkStudent->bind_param("s", $student_id);
        $checkStudent->execute();
        $checkStudent->bind_result($studentCount);
        $checkStudent->fetch();
        $checkStudent->close();

        if ($studentCount == 0) {
            $_SESSION['message'] = "Student with ID $student_id does not exist. Please add the student first.";
        } else {
            $subject_ids = isset($_POST['subject_ids']) ? $_POST['subject_ids'] : [];
            if (!empty($subject_ids)) {
                foreach ($subject_ids as $subject_id) {
                    $subject_id = $conn->real_escape_string(sanitizeInput($subject_id));
                    $sql = $conn->prepare("INSERT INTO student_enrollment (student_id, subject_id) VALUES (?, ?)");
                    $sql->bind_param("ss", $student_id, $subject_id);
                    if ($sql->execute()) {
                        $_SESSION['message'] = "Student enrolled successfully!";
                    } else {
                        $_SESSION['message'] = "Error during enrollment: " . $sql->error;
                        break;
                    }
                }
            } else {
                $_SESSION['message'] = "Select at least one subject.";
            }
        }
    }

    // Add Subject
    if (isset($_POST['add_subject'])) {
        $subject_id = $conn->real_escape_string(sanitizeInput($_POST['subject_id']));
        $subject_name = $conn->real_escape_string(sanitizeInput($_POST['subject_name']));
        $sql = $conn->prepare("INSERT INTO subjects (subject_id, subject_name) VALUES (?, ?)");
        $sql->bind_param("ss", $subject_id, $subject_name);
        if (!$sql->execute()) {
            if ($sql->errno == 1062) {
                $_SESSION['message'] = "Subject already exists!";
            } else {
                $_SESSION['message'] = "Error adding subject: " . $sql->error;
            }
        } else {
            $_SESSION['message'] = "Subject added successfully!";
        }
    }

    // Add Subject with Teacher Assignment
    if (isset($_POST['add_subject_with_teacher'])) {
        $subject_id = $conn->real_escape_string(sanitizeInput($_POST['subject_id']));
        $subject_name = $conn->real_escape_string(sanitizeInput($_POST['subject_name']));
        $teacher_id = $conn->real_escape_string(sanitizeInput($_POST['teacher_id']));

        // Start transaction
        $conn->begin_transaction();
        try {
            // Check if subject already exists
            $checkSubject = $conn->prepare("SELECT COUNT(*) FROM subjects WHERE subject_id = ?");
            $checkSubject->bind_param("s", $subject_id);
            $checkSubject->execute();
            $checkSubject->bind_result($subjectCount);
            $checkSubject->fetch();
            $checkSubject->close();

            if ($subjectCount > 0) {
                throw new Exception("Subject already exists!");
            }
            // Insert subject
            $sql = $conn->prepare("INSERT INTO subjects (subject_id, subject_name) VALUES (?, ?)");
            $sql->bind_param("ss", $subject_id, $subject_name);
            if (!$sql->execute()) {
                throw new Exception($sql->error);
            }
            // Check if teacher is already assigned to this subject
            $checkAssignment = $conn->prepare("SELECT COUNT(*) FROM teacher_assignments WHERE teacher_id = ? AND subject_id = ?");
            $checkAssignment->bind_param("ss", $teacher_id, $subject_id);
            $checkAssignment->execute();
            $checkAssignment->bind_result($assignmentCount);
            $checkAssignment->fetch();
            $checkAssignment->close();

            if ($assignmentCount > 0) {
                throw new Exception("Teacher already assigned to this subject!");
            }
            // Insert teacher assignment
            $assign_sql = $conn->prepare("INSERT INTO teacher_assignments (teacher_id, subject_id) VALUES (?, ?)");
            $assign_sql->bind_param("ss", $teacher_id, $subject_id);
            if (!$assign_sql->execute()) {
                throw new Exception("Error assigning teacher: " . $assign_sql->error);
            }
            // Commit transaction
            $conn->commit();
            $_SESSION['message'] = "Subject and teacher assignment added successfully!";
        } catch (Exception $e) {
            // Rollback transaction
            $conn->rollback();
            $_SESSION['message'] = "Error adding subject and teacher assignment: " . $e->getMessage();
        }
    }

    // Delete Subject with Teacher Assignment
    if (isset($_POST['delete_subject_with_teacher'])) {
        $subject_id = $conn->real_escape_string(sanitizeInput($_POST['subject_id']));
        $teacher_id = $conn->real_escape_string(sanitizeInput($_POST['teacher_id']));
        // Start transaction
        $conn->begin_transaction();
        try {
            // Delete teacher assignment first
            $sql = $conn->prepare("DELETE FROM teacher_assignments WHERE teacher_id = ? AND subject_id = ?");
            $sql->bind_param("ss", $teacher_id, $subject_id);
            if (!$sql->execute()) {
                throw new Exception("Error deleting teacher assignment: " . $sql->error);
            }
            // Delete subject
            $sql2 = $conn->prepare("DELETE FROM subjects WHERE subject_id = ?");
            $sql2->bind_param("s", $subject_id);
            if (!$sql2->execute()) {
                throw new Exception("Error deleting subject: " . $sql2->error);
            }
            // Commit transaction
            $conn->commit();
            $_SESSION['message'] = "Subject and teacher assignment deleted successfully!";
        } catch (Exception $e) {
            // Rollback transaction
            $conn->rollback();
            $_SESSION['message'] = "Error deleting subject and teacher assignment: " . $e->getMessage();
        }
    }

    // Delete All Students
    if (isset($_POST['delete_all_students'])) {
        $sql = "DELETE FROM students";
        if ($conn->query($sql) === TRUE) {
            $_SESSION['message'] = "All students deleted successfully!";
        } else {
            $_SESSION['message'] = "Error deleting all students: " . $conn->error;
        }
    }

    // Delete All Teachers
    if (isset($_POST['delete_all_teachers'])) {
        $sql = "DELETE FROM teachers";
        if ($conn->query($sql) === TRUE) {
            $_SESSION['message'] = "All teachers deleted successfully!";
        } else {
            $_SESSION['message'] = "Error deleting all teachers: " . $conn->error;
        }
    }

    // Delete All Subjects
    if (isset($_POST['delete_all_subjects'])) {
        $sql = "DELETE FROM subjects";
        if ($conn->query($sql) === TRUE) {
            $_SESSION['message'] = "All subjects deleted successfully!";
        } else {
            $_SESSION['message'] = "Error deleting all subjects: " . $conn->error;
        }
    }

    // Delete All Teacher Assignments
    if (isset($_POST['delete_all_teacher_assignments'])) {
        $sql = "DELETE FROM teacher_assignments";
        if ($conn->query($sql) === TRUE) {
            $_SESSION['message'] = "All teacher assignments deleted successfully!";
        } else {
            $_SESSION['message'] = "Error deleting all teacher assignments: " . $conn->error;
        }
    }

    // Delete All Student Enrollments
    if (isset($_POST['delete_all_student_enrollments'])) {
        $sql = "DELETE FROM student_enrollment";
        if ($conn->query($sql) === TRUE) {
            $_SESSION['message'] = "All student enrollments deleted successfully!";
        } else {
            $_SESSION['message'] = "Error deleting all student enrollments: " . $conn->error;
        }
    }

    // Delete All Attendance Records
    if (isset($_POST['delete_all_attendance'])) {
        $sql = "DELETE FROM attendance";
        if ($conn->query($sql) === TRUE) {
            $_SESSION['message'] = "All attendance records deleted successfully!";
        } else {
            $_SESSION['message'] = "Error deleting all attendance records: " . $conn->error;
        }
    }

    // Delete All Admins
    if (isset($_POST['delete_all_admins'])) {
        $sql = "DELETE FROM admins";
        if ($conn->query($sql) === TRUE) {
            $_SESSION['message'] = "All admins deleted successfully!";
        } else {
            $_SESSION['message'] = "Error deleting all admins: " . $conn->error;
        }
    }
    // Clear POST data after processing
    $_POST = array();
}

// Generate CSRF token for forms
$csrf_token = generateOrValidateToken();

// Fetch records for display
$students = $conn->query("SELECT * FROM students");
$teachers = $conn->query("SELECT * FROM teachers");
$subjects = $conn->query("SELECT * FROM subjects");
$teacher_assignments = $conn->query("SELECT * FROM teacher_assignments");
$student_enrollments = $conn->query("SELECT * FROM student_enrollment");
$attendance = $conn->query("SELECT * FROM attendance");
$admins = $conn->query("SELECT * FROM admins");
// Fetch Leave Requests for Leave Requests Management Section
$leave_requests = $conn->query("SELECT * FROM leave_requests ORDER BY id DESC");

// Prepare data for enrollment charts
$chart_data = [];
$enrollments_by_month = $conn->query("SELECT DATE_FORMAT(created_at, '%Y-%m') AS month, COUNT(*) AS count FROM student_enrollment GROUP BY month ORDER BY month");
if ($enrollments_by_month) {
    while ($row = $enrollments_by_month->fetch_assoc()) {
        $chart_data[] = $row;
    }
}

// After the existing query for subjects_result
$subjects_with_teachers = $conn->query("
    SELECT s.subject_id, s.subject_name, 
           GROUP_CONCAT(CONCAT(t.name, ' (', t.teacher_id, ')') SEPARATOR ', ') as teachers
    FROM subjects s
    LEFT JOIN teacher_assignments ta ON s.subject_id = ta.subject_id
    LEFT JOIN teachers t ON ta.teacher_id = t.teacher_id
    GROUP BY s.subject_id, s.subject_name
");
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin Panel</title>
  <!-- Bootstrap CSS and Font Awesome -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body {
      font-family: 'Segoe UI', sans-serif;
      background: #f8f9fa;
    }
    .navbar {
      margin-bottom: 20px;
    }
    .card-header {
      cursor: pointer;
    }
    .toggle-icon {
      transition: transform 0.3s ease;
    }
    .table-responsive { max-height: 400px; }
  </style>
</head>
<body>
  <!-- Navigation bar -->
  <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
    <div class="container-fluid">
      <a class="navbar-brand" href="#">Admin Panel</a>
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav ms-auto">
          <li class="nav-item">
            <a class="nav-link" href="admin_logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a>
          </li>
        </ul>
      </div>
    </div>
  </nav>

  <div class="container">
    <h1 class="mb-4 text-secondary"><i class="fas fa-tachometer-alt"></i> Dashboard</h1>
    <?php if (isset($_SESSION['message'])): ?>
      <div class="alert <?= (strpos($_SESSION['message'], 'Error') !== false) ? 'alert-danger' : 'alert-success' ?>">
        <i class="fas <?= (strpos($_SESSION['message'], 'Error') !== false) ? 'fa-exclamation-circle' : 'fa-check-circle' ?>"></i>
        <?= htmlspecialchars($_SESSION['message']) ?>
      </div>
      <?php unset($_SESSION['message']); ?>
    <?php endif; ?>

    <!-- Statistics Dashboard Cards -->
    <div class="row mb-4">
        <div class="col-md-2">
            <div class="card bg-primary text-white">
                <div class="card-body">
                    <h6 class="card-title">Total Students</h6>
                    <h3 class="card-text"><?= $dashboard_stats['total_students'] ?></h3>
                </div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="card bg-success text-white">
                <div class="card-body">
                    <h6 class="card-title">Total Teachers</h6>
                    <h3 class="card-text"><?= $dashboard_stats['total_teachers'] ?></h3>
                </div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="card bg-info text-white">
                <div class="card-body">
                    <h6 class="card-title">Total Subjects</h6>
                    <h3 class="card-text"><?= $dashboard_stats['total_subjects'] ?></h3>
                </div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="card bg-warning text-white">
                <div class="card-body">
                    <h6 class="card-title">Pending Leaves</h6>
                    <h3 class="card-text"><?= $dashboard_stats['pending_leaves'] ?></h3>
                </div>
            </div>
        </div>
        <div class="col-md-2">
            <div class="card bg-secondary text-white">
                <div class="card-body">
                    <h6 class="card-title">Today's Attendance</h6>
                    <h3 class="card-text"><?= $dashboard_stats['attendance_today'] ?></h3>
                </div>
            </div>
        </div>
    </div>

    <!-- Quick Actions Menu -->
    <div class="card mb-4">
        <div class="card-header bg-dark text-white">
            <h5 class="mb-0"><i class="fas fa-bolt"></i> Quick Actions</h5>
        </div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-3">
                    <div class="dropdown mb-2">
                        <button class="btn btn-outline-primary w-100 dropdown-toggle" type="button" data-bs-toggle="dropdown">
                            <i class="fas fa-download"></i> Export Attendance
                        </button>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="#" onclick="exportAttendance('all')">All Subjects</a></li>
                            <?php foreach ($all_subjects as $subject): ?>
                                <li><a class="dropdown-item" href="#" onclick="exportAttendance('<?= htmlspecialchars($subject['subject_id']) ?>')"><?= htmlspecialchars($subject['subject_name']) ?></a></li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="dropdown mb-2">
                        <button class="btn btn-outline-info w-100 dropdown-toggle" type="button" data-bs-toggle="dropdown">
                            <i class="fas fa-print"></i> Print Attendance
                        </button>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="#" onclick="printAttendance('all')">All Subjects</a></li>
                            <?php foreach ($all_subjects as $subject): ?>
                                <li><a class="dropdown-item" href="#" onclick="printAttendance('<?= htmlspecialchars($subject['subject_id']) ?>')"><?= htmlspecialchars($subject['subject_name']) ?></a></li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                </div>
                <div class="col-md-3">
                    <button class="btn btn-outline-warning w-100 mb-2" onclick="showBackupModal()">
                        <i class="fas fa-database"></i> Backup Data
                    </button>
                </div>
                <div class="col-md-3">
                    <button class="btn btn-outline-secondary w-100 mb-2" onclick="refreshDashboard()">
                        <i class="fas fa-sync-alt"></i> Refresh Data
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Chart Section -->
    <div class="card mb-3">
      <div class="card-header d-flex justify-content-between align-items-center" onclick="toggleCard('charts')">
        <h5 class="mb-0"><i class="fas fa-chart-line"></i> Enrollments Chart</h5>
        <div>
          <button class="btn btn-link text-secondary close-section" onclick="closeSection(event, 'charts')">
            <i class="fas fa-times"></i>
          </button>
          <i id="charts-icon" class="fas fa-chevron-down toggle-icon"></i>
        </div>
      </div>
      <div id="charts" class="card-body" style="display: none;">
        <canvas id="enrollmentChart"></canvas>
      </div>
    </div>

      <!-- Leave Requests Management Section -->
      <div class="card mb-3">
        <div class="card-header d-flex justify-content-between align-items-center" onclick="toggleCard('leave_requests')">
        <h5 class="mb-0"><i class="fas fa-envelope-open-text"></i> Leave Requests Management</h5>
        <div>
          <button class="btn btn-link text-secondary close-section" onclick="closeSection(event, 'leave_requests')">
            <i class="fas fa-times"></i>
          </button>
          <i id="leave_requests-icon" class="fas fa-chevron-down toggle-icon"></i>
        </div>
        </div>
        <div id="leave_requests" class="card-body" style="display: none;">
        <div class="table-responsive">
          <table class="table table-striped table-bordered">
          <thead class="table-dark">
            <tr>
            <th>#</th>
            <th>Student ID</th>
            <th>Name</th>
            <th>Email</th>
            <th>Reason</th>
            <th>File</th>
            <th>Status</th>
            <th>Denied Reason</th>
            <th>Submitted At</th>
            <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <?php if ($leave_requests && $leave_requests->num_rows > 0): ?>
            <?php while ($row = $leave_requests->fetch_assoc()): ?>
              <tr>
              <td><?= htmlspecialchars($row['id']) ?></td>
              <td><?= htmlspecialchars($row['student_id']) ?></td>
              <td><?= htmlspecialchars($row['name']) ?></td>
              <td><?= htmlspecialchars($row['email']) ?></td>
              <td><?= htmlspecialchars($row['reason']) ?></td>
              <td>
                <?php if (!empty($row['file'])): ?>
                <a href="uploads/<?= htmlspecialchars($row['file']) ?>" target="_blank">View File</a>
                <?php else: ?>
                N/A
                <?php endif; ?>
              </td>
              <td><?= htmlspecialchars($row['status']) ?></td>
              <td><?= (!empty($row['denied_reason'])) ? htmlspecialchars($row['denied_reason']) : 'N/A' ?></td>
              <td><?= htmlspecialchars($row['submitted_at'] ?? 'N/A') ?></td>
              <td>
                <form method="POST" class="d-grid">
                <input type="hidden" name="token" value="<?= $csrf_token ?>">
                <input type="hidden" name="request_id" value="<?= htmlspecialchars($row['id']) ?>">
                <select name="status" class="form-select form-select-sm mb-2" required>
                  <option value="pending" <?= ($row['status'] == 'pending') ? 'selected' : '' ?>>Pending</option>
                  <option value="approved" <?= ($row['status'] == 'approved') ? 'selected' : '' ?>>Approved</option>
                  <option value="denied" <?= ($row['status'] == 'denied') ? 'selected' : '' ?>>Denied</option>
                </select>
                <input type="text" name="denied_reason" class="form-control form-control-sm mb-2" placeholder="Denial Reason" value="<?= htmlspecialchars($row['denied_reason'] ?? '') ?>">
                <button type="submit" name="update_leave_request" class="btn btn-sm btn-warning">Update</button>
                <button type="submit" name="delete_leave_request" class="btn btn-sm btn-danger" onclick="return confirm('Are you sure you want to delete this leave request?')">Delete</button>
                </form>
              </td>
              </tr>
            <?php endwhile; ?>
            <?php else: ?>
            <tr>
              <td colspan="10" class="text-center">No leave requests found.</td>
            </tr>
            <?php endif; ?>
          </tbody>
          </table>
        </div>
        </div>
      </div>


    <!-- Students Management Section -->
    <div class="card mb-3">
      <div class="card-header d-flex justify-content-between align-items-center" onclick="toggleCard('students')">
        <h5 class="mb-0"><i class="fas fa-users"></i> Manage Students</h5>
        <div>
          <button class="btn btn-link text-secondary close-section" onclick="closeSection(event, 'students')">
            <i class="fas fa-times"></i>
          </button>
          <i id="students-icon" class="fas fa-chevron-down toggle-icon"></i>
        </div>
      </div>
      <div id="students" class="card-body" style="display: none;">
        <!-- Search Student -->
        <div class="mb-3">
          <input type="text" class="form-control" id="studentSearchInput" placeholder="Search by Student ID, Name or Email">
        </div>
        <!-- Add Student Form -->
        <form method="POST" class="row g-3 mb-3">
          <input type="hidden" name="token" value="<?= $csrf_token ?>">
          <div class="col-md-2">
            <input type="text" class="form-control" name="student_id" placeholder="Student ID" required>
          </div>
          <div class="col-md-2">
            <input type="text" class="form-control" name="name" placeholder="Name" required>
          </div>
          <div class="col-md-2">
            <input type="email" class="form-control" name="email" placeholder="Email" required>
          </div>
          <div class="col-md-2">
            <select class="form-select" name="medical_or_preenj" required>
              <option value="Medical">Medical</option>
              <option value="Pre-Engineering">Pre-Engineering</option>
            </select>
          </div>
          <div class="col-md-2">
            <input type="password" class="form-control" name="password" placeholder="Password" required>
          </div>
          <div class="col-md-2">
            <input type="submit" class="btn btn-primary" name="add_student" value="Add Student">
          </div>
        </form>
        <!-- Update Student Form -->
        <form method="POST" class="row g-3 mb-3">
          <input type="hidden" name="token" value="<?= $csrf_token ?>">
          <div class="col-md-2">
            <input type="text" class="form-control" name="student_id" placeholder="Student ID to update" required>
          </div>
          <div class="col-md-2">
            <input type="text" class="form-control" name="name" placeholder="New Name" required>
          </div>
          <div class="col-md-2">
            <input type="email" class="form-control" name="email" placeholder="New Email" required>
          </div>
          <div class="col-md-2">
            <select class="form-select" name="medical_or_preenj" required>
              <option value="Medical">Medical</option>
              <option value="Pre-Engineering">Pre-Engineering</option>
            </select>
          </div>
          <div class="col-md-2">
            <input type="submit" class="btn btn-warning" name="update_student" value="Update Student">
          </div>
        </form>
        <!-- Delete Student Form -->
        <form method="POST" class="row g-3 mb-3">
          <input type="hidden" name="token" value="<?= $csrf_token ?>">
          <div class="col-md-3">
            <input type="text" class="form-control" name="student_id" placeholder="Student ID to delete" required>
          </div>
          <div class="col-md-2">
            <input type="submit" class="btn btn-danger" name="delete_student" value="Delete Student">
          </div>
        </form>
        <!-- Students Table -->
        <div class="table-responsive">
          <table class="table table-bordered table-hover" id="studentsTable">
            <thead class="table-light">
              <tr>
                <th>Student ID</th>
                <th>Name</th>
                <th>Email</th>
                <th>Stream</th>
                <th>Created At</th>
              </tr>
            </thead>
            <tbody>
              <?php while ($row = $students->fetch_assoc()): ?>
              <tr>
                <td><?= htmlspecialchars($row['student_id']) ?></td>
                <td><?= htmlspecialchars($row['name']) ?></td>
                <td><?= htmlspecialchars($row['email']) ?></td>
                <td><?= htmlspecialchars($row['medical_or_preenj']) ?></td>
                <td><?= htmlspecialchars($row['created_at']) ?></td>
              </tr>
              <?php endwhile; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Teacher Assignments Section -->
    <div class="card mb-3">
      <div class="card-header d-flex justify-content-between align-items-center" onclick="toggleCard('assignments')">
        <h5 class="mb-0"><i class="fas fa-tasks"></i> Teacher Assignments</h5>
        <div>
          <button class="btn btn-link text-secondary close-section" onclick="closeSection(event, 'assignments')">
            <i class="fas fa-times"></i>
          </button>
          <i id="assignments-icon" class="fas fa-chevron-down toggle-icon"></i>
        </div>
      </div>
      <div id="assignments" class="card-body" style="display: none;">
        <!-- Teacher ID Guide -->
        <div class="mb-3">
          <label class="form-label">Teacher ID Guide:</label>
          <?php
          $teachers_result = $conn->query("SELECT teacher_id, name FROM teachers");
          if ($teachers_result) {
            while ($teacher = $teachers_result->fetch_assoc()):
          ?>
              <div class="form-check form-check-inline">
                <small><?= htmlspecialchars($teacher['teacher_id']) ?>: <?= htmlspecialchars($teacher['name']) ?></small>
              </div>
          <?php
            endwhile;
          }
          ?>
        </div>
        <form method="POST" class="row g-3 mb-3">
          <input type="hidden" name="token" value="<?= $csrf_token ?>">
          <div class="col-md-4">
            <input type="text" class="form-control" name="teacher_id" placeholder="Teacher ID" required>
          </div>
          <div class="col-md-4">
            <input type="text" class="form-control" name="subject_id" placeholder="Subject ID" required>
          </div>
          <div class="col-md-4">
            <input type="submit" class="btn btn-primary" name="add_teacher_assignment" value="Add Assignment">
          </div>
        </form>
        <form method="POST" class="row g-3 mb-3">
          <input type="hidden" name="token" value="<?= $csrf_token ?>">
          <div class="col-md-4">
            <input type="text" class="form-control" name="id" placeholder="Assignment ID to delete" required>
          </div>
          <div class="col-md-4">
            <input type="submit" class="btn btn-danger" name="delete_teacher_assignment" value="Delete Assignment">
          </div>
        </form>
        <!-- Delete All Teacher Assignments Form -->
        <form method="POST" class="row g-3 mb-3">
          <input type="hidden" name="token" value="<?= $csrf_token ?>">
          <div class="col-md-3">
            <input type="submit" class="btn btn-danger" name="delete_all_teacher_assignments" value="Delete All Teacher Assignments" onclick="return confirm('Are you sure you want to delete all teacher assignments? This cannot be undone.');">
          </div>
        </form>
        <div class="table-responsive">
          <table class="table table-bordered table-hover">
            <thead class="table-light">
              <tr>
                <th>ID</th>
                <th>Teacher ID</th>
                <th>Subject ID</th>
              </tr>
            </thead>
            <tbody>
              <?php while ($row = $teacher_assignments->fetch_assoc()): ?>
              <tr>
                <td><?= htmlspecialchars($row['id']) ?></td>
                <td><?= htmlspecialchars($row['teacher_id']) ?></td>
                <td><?= htmlspecialchars($row['subject_id']) ?></td>
              </tr>
              <?php endwhile; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Subjects Management Section -->
    <div class="card mb-3">
      <div class="card-header d-flex justify-content-between align-items-center" onclick="toggleCard('subjects_section')">
        <h5 class="mb-0"><i class="fas fa-book"></i> Manage Subjects</h5>
        <div>
          <button class="btn btn-link text-secondary close-section" onclick="closeSection(event, 'subjects_section')">
            <i class="fas fa-times"></i>
          </button>
          <i id="subjects_section-icon" class="fas fa-chevron-down toggle-icon"></i>
        </div>
      </div>
      <div id="subjects_section" class="card-body" style="display: none;">
        <!-- Add Subject Form -->
        <form method="POST" class="row g-3 mb-3">
          <input type="hidden" name="token" value="<?= $csrf_token ?>">
          <div class="col-md-4">
            <input type="text" class="form-control" name="subject_id" placeholder="Subject ID" required>
          </div>
          <div class="col-md-4">
            <input type="text" class="form-control" name="subject_name" placeholder="Subject Name" required>
          </div>
          <div class="col-md-4">
            <input type="submit" class="btn btn-primary" name="add_subject" value="Add Subject">
          </div>
        </form>
        <!-- Add Subject With Teacher Assignment Form -->
        <form method="POST" class="row g-3 mb-3">
          <input type="hidden" name="token" value="<?= $csrf_token ?>">
          <div class="col-md-3">
            <input type="text" class="form-control" name="subject_id" placeholder="Subject ID" required>
          </div>
          <div class="col-md-3">
            <input type="text" class="form-control" name="subject_name" placeholder="Subject Name" required>
          </div>
          <div class="col-md-3">
            <input type="text" class="form-control" name="teacher_id" placeholder="Teacher ID" required>
          </div>
          <div class="col-md-3">
            <input type="submit" class="btn btn-primary" name="add_subject_with_teacher" value="Add Subject with Teacher">
          </div>
        </form>
        <!-- Delete Subject With Teacher Assignment Form -->
        <form method="POST" class="row g-3 mb-3">
          <input type="hidden" name="token" value="<?= $csrf_token ?>">
          <div class="col-md-3">
            <input type="text" class="form-control" name="subject_id" placeholder="Subject ID" required>
          </div>
          <div class="col-md-3">
            <input type="text" class="form-control" name="teacher_id" placeholder="Teacher ID" required>
          </div>
          <div class="col-md-3">
            <input type="submit" class="btn btn-danger" name="delete_subject_with_teacher" value="Delete Subject with Teacher">
          </div>
        </form>
        <!-- Delete All Subjects Form -->
        <form method="POST" class="row g-3 mb-3">
          <input type="hidden" name="token" value="<?= $csrf_token ?>">
          <div class="col-md-3">
            <input type="submit" class="btn btn-danger" name="delete_all_subjects" value="Delete All Subjects" onclick="return confirm('Are you sure you want to delete all subjects? This cannot be undone.');">
          </div>
        </form>
        <!-- Search Subject -->
        <div class="mb-3">
            <input type="text" class="form-control" id="subjectSearchInput" placeholder="Search by Subject ID or Name">
        </div>
        <!-- Subjects Table -->
        <div class="table-responsive">
            <table class="table table-bordered table-hover" id="subjectsTable">
                <thead class="table-light">
                    <tr>
                        <th>Subject ID</th>
                        <th>Subject Name</th>
                        <th>Assigned Teachers</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while ($row = $subjects_with_teachers->fetch_assoc()): ?>
                        <tr>
                            <td><?= htmlspecialchars($row['subject_id']) ?></td>
                            <td><?= htmlspecialchars($row['subject_name']) ?></td>
                            <td><?= htmlspecialchars($row['teachers'] ?: 'No teacher assigned') ?></td>
                        </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
      </div>
    </div>

    <!-- Student Enrollment Section -->
    <div class="card mb-3">
      <div class="card-header d-flex justify-content-between align-items-center" onclick="toggleCard('enrollments')">
        <h5 class="mb-0"><i class="fas fa-clipboard-list"></i> Student Enrollments</h5>
        <div>
          <button class="btn btn-link text-secondary close-section" onclick="closeSection(event, 'enrollments')">
            <i class="fas fa-times"></i>
          </button>
          <i id="enrollments-icon" class="fas fa-chevron-down toggle-icon"></i>
        </div>
      </div>
      <div id="enrollments" class="card-body" style="display: none;">
        <form method="POST" class="row g-3 mb-3">
          <input type="hidden" name="token" value="<?= $csrf_token ?>">
          <div class="col-md-4">
            <input type="text" class="form-control" name="student_id" placeholder="Student ID" required>
          </div>
          <div class="col-md-8">
            <label class="form-label">Select Subjects:</label>
            <?php foreach ($all_subjects as $subject): ?>
              <div class="form-check form-check-inline">
                <input class="form-check-input" type="checkbox" name="subject_ids[]" value="<?= htmlspecialchars($subject['subject_id']) ?>">
                <label class="form-check-label"><?= htmlspecialchars($subject['subject_name']) ?></label>
              </div>
            <?php endforeach; ?>
          </div>
          <div class="col-md-12">
            <input type="submit" class="btn btn-primary" name="add_student_enrollment" value="Enroll Student">
          </div>
        </form>
        <form method="POST" class="row g-3 mb-3">
          <input type="hidden" name="token" value="<?= $csrf_token ?>">
          <div class="col-md-4">
            <input type="text" class="form-control" name="id" placeholder="Enrollment ID to delete" required>
          </div>
          <div class="col-md-4">
            <input type="submit" class="btn btn-danger" name="delete_student_enrollment" value="Delete Enrollment">
          </div>
        </form>
        <!-- Delete All Student Enrollments Form -->
        <form method="POST" class="row g-3 mb-3">
          <input type="hidden" name="token" value="<?= $csrf_token ?>">
          <div class="col-md-3">
            <input type="submit" class="btn btn-danger" name="delete_all_student_enrollments" value="Delete All Student Enrollments" onclick="return confirm('Are you sure you want to delete all student enrollments? This cannot be undone.');">
          </div>
        </form>
        <!-- Search Enrollment -->
        <div class="mb-3">
            <input type="text" class="form-control" id="enrollmentSearchInput" placeholder="Search by Student ID or Subject ID">
        </div>
        <div class="table-responsive">
          <table class="table table-bordered table-hover" id="enrollmentsTable">
            <thead class="table-light">
              <tr>
                <th>ID</th>
                <th>Student ID</th>
                <th>Subject ID</th>
              </tr>
            </thead>
            <tbody>
              <?php
              $student_enrollments_result = $conn->query("SELECT * FROM student_enrollment");
              while ($row = $student_enrollments_result->fetch_assoc()): ?>
              <tr>
                <td><?= htmlspecialchars($row['id']) ?></td>
                <td><?= htmlspecialchars($row['student_id']) ?></td>
                <td><?= htmlspecialchars($row['subject_id']) ?></td>
              </tr>
              <?php endwhile; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Attendance Management Section -->
    <div class="card mb-3">
      <div class="card-header d-flex justify-content-between align-items-center" onclick="toggleCard('attendance')">
        <h5 class="mb-0"><i class="fas fa-clipboard-check"></i> Attendance Management</h5>
        <div>
          <button class="btn btn-link text-secondary close-section" onclick="closeSection(event, 'attendance')">
            <i class="fas fa-times"></i>
          </button>
          <i id="attendance-icon" class="fas fa-chevron-down toggle-icon"></i>
        </div>
      </div>
      <div id="attendance" class="card-body" style="display: none;">
        <!-- Subject ID Guide -->
        <div class="mb-3">
          <label class="form-label">Subject ID Guide:</label>
          <?php foreach ($all_subjects as $subject): ?>
            <div class="form-check form-check-inline">
              <small><?= htmlspecialchars($subject['subject_id']) ?>: <?= htmlspecialchars($subject['subject_name']) ?></small>
            </div>
          <?php endforeach; ?>
        </div>
        <form method="POST" class="row g-3 mb-3">
          <input type="hidden" name="token" value="<?= $csrf_token ?>">
          <div class="col-md-3">
            <input type="text" class="form-control" name="student_ids" placeholder="Student IDs (comma-separated)" required>
          </div>
          <div class="col-md-2">
            <input type="text" class="form-control" name="subject_id" placeholder="Subject ID" required>
          </div>
          <div class="col-md-2">
            <input type="date" class="form-control" name="class_date" required>
          </div>
          <div class="col-md-2">
            <input type="number" class="form-control" name="week_number" placeholder="Week #" required>
          </div>
          <div class="col-md-2">
            <select class="form-select" name="status" required>
              <option value="P">Present</option>
              <option value="A">Absent</option>
              <option value="L">Leave</option>
            </select>
          </div>
          <div class="col-md-1">
            <input type="submit" class="btn btn-primary" name="add_attendance" value="Add">
          </div>
        </form>
        <form method="POST" class="row g-3 mb-3">
          <input type="hidden" name="token" value="<?= $csrf_token ?>">
          <div class="col-md-3">
            <input type="text" class="form-control" name="id" placeholder="Attendance ID to delete" required>
          </div>
          <div class="col-md-3">
            <input type="submit" class="btn btn-danger" name="delete_attendance" value="Delete">
          </div>
        </form>
        <!-- Delete All Attendance Records Form -->
        <form method="POST" class="row g-3 mb-3">
          <input type="hidden" name="token" value="<?= $csrf_token ?>">
          <div class="col-md-3">
            <input type="submit" class="btn btn-danger" name="delete_all_attendance" value="Delete All Attendance Records" onclick="return confirm('Are you sure you want to delete all attendance records? This cannot be undone.');">
          </div>
        </form>
        <!-- Attendance Filters -->
        <div class="row mb-3">
            <div class="col-md-3">
                <input type="text" class="form-control" id="attendanceSearchInput" placeholder="Search by Student ID">
            </div>
            <div class="col-md-3">
                <input type="date" class="form-control" id="attendanceDateFilter" placeholder="Filter by Date">
            </div>
            <div class="col-md-3">
                <select class="form-select" id="attendanceWeekFilter">
                    <option value="">All Weeks</option>
                    <?php for($i=1; $i<=52; $i++): ?>
                        <option value="<?= $i ?>">Week <?= $i ?></option>
                    <?php endfor; ?>
                </select>
            </div>
            <div class="col-md-3">
                <select class="form-select" id="attendanceStatusFilter">
                    <option value="">All Status</option>
                    <option value="P">Present</option>
                    <option value="A">Absent</option>
                    <option value="L">Leave</option>
                </select>
            </div>
        </div>
        <div class="table-responsive">
          <table class="table table-bordered table-hover" id="attendanceTable">
            <thead class="table-light">
              <tr>
                <th>ID</th>
                <th>Student ID</th>
                <th>Subject ID</th>
                <th>Date</th>
                <th>Week</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              <?php while ($row = $attendance_with_details->fetch_assoc()): ?>
              <tr>
                <td><?= htmlspecialchars($row['id']) ?></td>
                <td data-student-id="<?= htmlspecialchars($row['student_id']) ?>" 
                    data-student-name="<?= htmlspecialchars($row['student_name']) ?>"><?= htmlspecialchars($row['student_id']) ?></td>
                <td data-subject-id="<?= htmlspecialchars($row['subject_id']) ?>"
                    data-subject-name="<?= htmlspecialchars($row['subject_name']) ?>"><?= htmlspecialchars($row['subject_id']) ?></td>
                <td><?= htmlspecialchars($row['class_date']) ?></td>
                <td><?= htmlspecialchars($row['week_number']) ?></td>
                <td><?= htmlspecialchars($row['status']) ?></td>
              </tr>
              <?php endwhile; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Admins Management Section -->
    <div class="card mb-3">
      <div class="card-header d-flex justify-content-between align-items-center" onclick="toggleCard('admins')">
        <h5 class="mb-0"><i class="fas fa-user-shield"></i> Admin Management</h5>
        <div>
          <button class="btn btn-link text-secondary close-section" onclick="closeSection(event, 'admins')">
            <i class="fas fa-times"></i>
          </button>
          <i id="admins-icon" class="fas fa-chevron-down toggle-icon"></i>
        </div>
      </div>
      <div id="admins" class="card-body" style="display: none;">
        <form method="POST" class="row g-3 mb-3">
          <input type="hidden" name="token" value="<?= $csrf_token ?>">
          <div class="col-md-3">
            <input type="text" class="form-control" name="name" placeholder="Name" required>
          </div>
          <div class="col-md-3">
            <input type="email" class="form-control" name="email" placeholder="Email" required>
          </div>
          <div class="col-md-3">
            <input type="password" class="form-control" name="password" placeholder="Password" required>
          </div>
          <div class="col-md-3">
            <input type="submit" class="btn btn-primary" name="add_admin" value="Add Admin">
          </div>
        </form>
        <form method="POST" class="row g-3 mb-3">
          <input type="hidden" name="token" value="<?= $csrf_token ?>">
          <div class="col-md-3">
            <input type="text" class="form-control" name="admin_id" placeholder="Admin ID to delete" required>
          </div>
          <div class="col-md-3">
            <input type="submit" class="btn btn-danger" name="delete_admin" value="Delete Admin">
          </div>
        </form>
        <!-- Delete All Admins Form -->
        <form method="POST" class="row g-3 mb-3">
          <input type="hidden" name="token" value="<?= $csrf_token ?>">
          <div class="col-md-3">
            <input type="submit" class="btn btn-danger" name="delete_all_admins" value="Delete All Admins" onclick="return confirm('Are you sure you want to delete all admins? This cannot be undone.');">
          </div>
        </form>
        <div class="table-responsive">
          <table class="table table-bordered table-hover">
            <thead class="table-light">
              <tr>
                <th>Admin ID</th>
                <th>Name</th>
                <th>Email</th>
                <th>Created At</th>
              </tr>
            </thead>
            <tbody>
              <?php while ($row = $admins->fetch_assoc()): ?>
              <tr>
                <td><?= htmlspecialchars($row['admin_id']) ?></td>
                <td><?= htmlspecialchars($row['name']) ?></td>
                <td><?= htmlspecialchars($row['email']) ?></td>
                <td><?= htmlspecialchars($row['created_at']) ?></td>
              </tr>
              <?php endwhile; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <!-- Backup Modal -->
  <div class="modal fade" id="backupModal" tabindex="-1">
      <div class="modal-dialog">
          <div class="modal-content">
              <div class="modal-header">
                  <h5 class="modal-title">Backup Database</h5>
                  <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
              </div>
              <div class="modal-body">
                  <p>Select the data you want to backup:</p>
                  <div class="form-check">
                      <input class="form-check-input" type="checkbox" value="" id="backupStudents" checked>
                      <label class="form-check-label" for="backupStudents">Students Data</label>
                  </div>
                  <div class="form-check">
                      <input class="form-check-input" type="checkbox" value="" id="backupAttendance" checked>
                      <label class="form-check-label" for="backupAttendance">Attendance Records</label>
                  </div>
                  <div class="form-check">
                      <input class="form-check-input" type="checkbox" value="" id="backupSubjects" checked>
                      <label class="form-check-label" for="backupSubjects">Subjects Data</label>
                  </div>
              </div>
              <div class="modal-footer">
                  <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                  <button type="button" class="btn btn-primary" onclick="performBackup()">Start Backup</button>
              </div>
          </div>
      </div>
  </div>

  <!-- Sidebar -->
  <div class="sidebar">
    <a href="#dashboard" class="active" onclick="scrollToSection('dashboard')">
      <i class="fas fa-tachometer-alt"></i> Dashboard
    </a>
    <a href="#leave_requests" onclick="scrollToSection('leave_requests')">
      <i class="fas fa-envelope-open-text"></i> Leave Requests
    </a>
    <a href="#students" onclick="scrollToSection('students')">
      <i class="fas fa-users"></i> Students
    </a>
    <a href="#assignments" onclick="scrollToSection('assignments')">
      <i class="fas fa-tasks"></i> Teacher Assignments
    </a>
    <a href="#subjects_section" onclick="scrollToSection('subjects_section')">
      <i class="fas fa-book"></i> Subjects
    </a>
    <a href="#enrollments" onclick="scrollToSection('enrollments')">
      <i class="fas fa-clipboard-list"></i> Enrollments
    </a>
    <a href="#attendance" onclick="scrollToSection('attendance')">
      <i class="fas fa-clipboard-check"></i> Attendance
    </a>
    <a href="#admins" onclick="scrollToSection('admins')">
      <i class="fas fa-user-shield"></i> Admins
    </a>
  </div>

  <!-- Sidebar Toggle Button -->
  <button class="sidebar-toggle btn btn-link">
    <i class="fas fa-bars fa-2x"></i>
  </button>

  <!-- JavaScript: Bootstrap and custom scripts -->
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    document.addEventListener("DOMContentLoaded", () => {
      // Initialize Chart.js for enrollment data
      const ctx = document.getElementById('enrollmentChart').getContext('2d');
      new Chart(ctx, {
        type: 'line',
        data: {
          labels: <?= json_encode(array_column($chart_data, 'month')) ?>,
          datasets: [{
            label: 'Enrollments',
            data: <?= json_encode(array_column($chart_data, 'count')) ?>,
            borderColor: 'rgba(52,152,219,1)',
            backgroundColor: 'rgba(52,152,219,0.2)',
            fill: true,
            tension: 0.3
          }]
        },
        options: {
          responsive: true,
          scales: {
            x: { title: { display: true, text: 'Month' } },
            y: { beginAtZero: true, title: { display: true, text: 'Count' } }
          }
        }
      });

      // Student Search Filter
      const searchInput = document.getElementById('studentSearchInput');
      searchInput.addEventListener('keyup', () => {
        const filter = searchInput.value.toUpperCase();
        const table = document.getElementById('studentsTable');
        const trs = table.getElementsByTagName('tr');
        Array.from(trs).forEach(tr => {
          const tds = tr.getElementsByTagName('td');
          let visible = false;
          Array.from(tds).forEach(td => {
            if (td && td.textContent.toUpperCase().indexOf(filter) > -1) {
              visible = true;
            }
          });
          tr.style.display = visible ? "" : "none";
        });
      });

      // Add new search initializations
      searchFunction('subjectSearchInput', 'subjectsTable', [0, 1]);
      searchFunction('enrollmentSearchInput', 'enrollmentsTable', [1, 2]);
      
      // Attendance filters
      const attendanceFilter = () => {
          const searchText = document.getElementById('attendanceSearchInput').value.toUpperCase();
          const dateFilter = document.getElementById('attendanceDateFilter').value;
          const weekFilter = document.getElementById('attendanceWeekFilter').value;
          const statusFilter = document.getElementById('attendanceStatusFilter').value;
          
          const table = document.getElementById('attendanceTable');
          const trs = table.getElementsByTagName('tr');
          
          Array.from(trs).forEach(tr => {
              const tds = tr.getElementsByTagName('td');
              if (tds.length) {
                  const studentId = tds[1].textContent.toUpperCase();
                  const date = tds[3].textContent;
                  const week = tds[4].textContent;
                  const status = tds[5].textContent;
                  
                  const matchesSearch = studentId.includes(searchText);
                  const matchesDate = !dateFilter || date === dateFilter;
                  const matchesWeek = !weekFilter || week === weekFilter;
                  const matchesStatus = !statusFilter || status === statusFilter;
                  
                  tr.style.display = (matchesSearch && matchesDate && matchesWeek && matchesStatus) ? "" : "none";
              }
          });
      };
      
      // Add event listeners for attendance filters
      document.getElementById('attendanceSearchInput').addEventListener('keyup', attendanceFilter);
      document.getElementById('attendanceDateFilter').addEventListener('change', attendanceFilter);
      document.getElementById('attendanceWeekFilter').addEventListener('change', attendanceFilter);
      document.getElementById('attendanceStatusFilter').addEventListener('change', attendanceFilter);
    });

    // Toggle card visibility and store state in localStorage
    function toggleCard(cardId) {
      const cardBody = document.getElementById(cardId);
      const icon = document.getElementById(cardId + "-icon");
      if (cardBody.style.display === "none" || cardBody.style.display === "") {
        cardBody.style.display = "block";
        icon.style.transform = "rotate(180deg)";
      } else {
        cardBody.style.display = "none";
        icon.style.transform = "rotate(0deg)";
      }
    }

    // Add these search functions to your existing JavaScript
    const searchFunction = (inputId, tableId, columns) => {
        const input = document.getElementById(inputId);
        input.addEventListener('keyup', () => {
            const filter = input.value.toUpperCase();
            const table = document.getElementById(tableId);
            const trs = table.getElementsByTagName('tr');
            
            Array.from(trs).forEach(tr => {
                const tds = tr.getElementsByTagName('td');
                let visible = false;
                columns.forEach(col => {
                    if (tds[col] && tds[col].textContent.toUpperCase().indexOf(filter) > -1) {
                        visible = true;
                    }
                });
                tr.style.display = visible ? "" : "none";
            });
        });
    };

    // Add after existing JavaScript code
    function exportTableToCSV(tableId, filename) {
        const table = document.getElementById(tableId);
        let csv = [];
        const rows = table.getElementsByTagName('tr');
        
        for (let i = 0; i < rows.length; i++) {
            const row = [], cols = rows[i].getElementsByTagName('td');
            if (cols.length === 0) continue; // Skip if no columns
            
            for (let j = 0; j < cols.length; j++) {
                row.push(cols[j].innerText);
            }
            csv.push(row.join(','));
        }
        
        const csvFile = new Blob([csv.join('\n')], { type: 'text/csv' });
        const downloadLink = document.createElement('a');
        downloadLink.download = filename;
        downloadLink.href = window.URL.createObjectURL(csvFile);
        downloadLink.style.display = 'none';
        document.body.appendChild(downloadLink);
        downloadLink.click();
    }

    function printReport(section) {
        const printContent = document.getElementById(section).innerHTML;
        const originalContent = document.body.innerHTML;
        document.body.innerHTML = printContent;
        window.print();
        document.body.innerHTML = originalContent;
    }

    function showBackupModal() {
        const modal = new bootstrap.Modal(document.getElementById('backupModal'));
        modal.show();
    }

    function performBackup() {
        // Simulate backup process
        const progress = document.createElement('div');
        progress.className = 'progress-bar';
        progress.style.width = '0%';
        document.querySelector('.modal-body').appendChild(progress);
        
        let width = 0;
        const interval = setInterval(() => {
            if (width >= 100) {
                clearInterval(interval);
                alert('Backup completed successfully!');
                bootstrap.Modal.getInstance(document.getElementById('backupModal')).hide();
            } else {
                width++;
                progress.style.width = width + '%';
            }
        }, 20);
    }

    function refreshDashboard() {
        location.reload();
    }

    // Dark mode toggle
    function toggleDarkMode() {
        document.body.classList.toggle('dark-mode');
        localStorage.setItem('darkMode', document.body.classList.contains('dark-mode'));
    }

    // Check dark mode preference on load
    if (localStorage.getItem('darkMode') === 'true') {
        document.body.classList.add('dark-mode');
    }

    // Add to your existing DOMContentLoaded event
    document.addEventListener('DOMContentLoaded', function() {
        // Existing code...
        
        // Initialize tooltips
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    });

    function exportAttendance(subjectId) {
        const table = document.getElementById('attendanceTable');
        const rows = Array.from(table.getElementsByTagName('tr'));
        let csv = [];
        
        // Add header
        const headers = ['Student ID', 'Student Name', 'Subject', 'Date', 'Week', 'Status'];
        csv.push(headers.join(','));
        
        // Filter and format rows
        rows.forEach(row => {
            const cols = row.getElementsByTagName('td');
            if (cols.length > 0) {
                if (subjectId === 'all' || cols[2].textContent === subjectId) {
                    const rowData = [
                        cols[1].textContent, // Student ID
                        document.querySelector(`[data-student-id="${cols[1].textContent}"]`)?.dataset.studentName || '', // Student Name
                        document.querySelector(`[data-subject-id="${cols[2].textContent}"]`)?.dataset.subjectName || cols[2].textContent, // Subject
                        cols[3].textContent, // Date
                        cols[4].textContent, // Week
                        cols[5].textContent  // Status
                    ];
                    csv.push(rowData.join(','));
                }
            }
        });
        
        // Download CSV
        const filename = `attendance_${subjectId}_${new Date().toISOString().slice(0,10)}.csv`;
        const csvContent = csv.join('\n');
        const blob = new Blob([csvContent], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        window.URL.revokeObjectURL(url);
    }

    function printAttendance(subjectId) {
        const table = document.getElementById('attendanceTable');
        const rows = Array.from(table.getElementsByTagName('tr'));
        
        // Create print content
        let printContent = `
            <style>
                @media print {
                    table { width: 100%; border-collapse: collapse; margin-bottom: 1rem; }
                    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                    thead { background-color: #f8f9fa; }
                    h3 { margin-bottom: 1rem; }
                }
            </style>
            <h3>Attendance Report - ${subjectId === 'all' ? 'All Subjects' : `Subject: ${subjectId}`}</h3>
            <table>
                <thead>
                    <tr>
                        <th>Student ID</th>
                        <th>Student Name</th>
                        <th>Subject</th>
                        <th>Date</th>
                        <th>Week</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
        `;
        
        // Filter and add rows
        rows.forEach(row => {
            const cols = row.getElementsByTagName('td');
            if (cols.length > 0) {
                if (subjectId === 'all' || cols[2].textContent === subjectId) {
                    printContent += `<tr>
                        <td>${cols[1].textContent}</td>
                        <td>${document.querySelector(`[data-student-id="${cols[1].textContent}"]`)?.dataset.studentName || ''}</td>
                        <td>${document.querySelector(`[data-subject-id="${cols[2].textContent}"]`)?.dataset.subjectName || cols[2].textContent}</td>
                        <td>${cols[3].textContent}</td>
                        <td>${cols[4].textContent}</td>
                        <td>${cols[5].textContent}</td>
                    </tr>`;
                }
            }
        });
        
        printContent += '</tbody></table>';
        
        // Print
        const originalContent = document.body.innerHTML;
        document.body.innerHTML = printContent;
        window.print();
        document.body.innerHTML = originalContent;
        
        // Reinitialize event listeners and other functions
        location.reload();
    }

    // Add to your existing JavaScript
    document.addEventListener('DOMContentLoaded', function() {
      // Sidebar toggle
      const sidebar = document.querySelector('.sidebar');
      const sidebarToggle = document.querySelector('.sidebar-toggle');
      const contentWrapper = document.querySelector('.container');

      sidebarToggle.addEventListener('click', function() {
        sidebar.classList.toggle('active');
        contentWrapper.classList.toggle('sidebar-active');
      });

      // Close sidebar when clicking outside
      document.addEventListener('click', function(e) {
        if (!sidebar.contains(e.target) && !sidebarToggle.contains(e.target)) {
          sidebar.classList.remove('active');
          contentWrapper.classList.remove('sidebar-active');
        }
      });

      // Highlight active section in sidebar
      const sections = document.querySelectorAll('.card');
      window.addEventListener('scroll', function() {
        let current = '';
        sections.forEach(section => {
          const sectionTop = section.offsetTop;
          if (scrollY >= sectionTop - 60) {
            current = section.id;
          }
        });

        document.querySelectorAll('.sidebar a').forEach(a => {
          a.classList.remove('active');
          if (a.getAttribute('href').slice(1) === current) {
            a.classList.add('active');
          }
        });
      });
    });

    // Smooth scroll to section
    function scrollToSection(sectionId) {
      const section = document.getElementById(sectionId);
      if (section) {
        // Show the section
        section.style.display = "block";
        document.getElementById(sectionId + "-icon").style.transform = "rotate(180deg)";
        
        // Smooth scroll
        section.scrollIntoView({ 
          behavior: 'smooth',
          block: 'start'
        });
        
        // Update sidebar active state
        document.querySelectorAll('.sidebar a').forEach(a => {
          a.classList.remove('active');
          if (a.getAttribute('href').slice(1) === sectionId) {
            a.classList.add('active');
          }
        });
      }
    }

    // Add close section function
    function closeSection(event, sectionId) {
      event.stopPropagation(); // Prevent the card header click event
      const section = document.getElementById(sectionId);
      const icon = document.getElementById(sectionId + "-icon");
      section.style.display = "none";
      icon.style.transform = "rotate(0deg)";
    }

    // Add to your DOMContentLoaded event
    document.addEventListener('DOMContentLoaded', function() {
      // Add close button to all card headers
      document.querySelectorAll('.card-header').forEach(header => {
        const sectionId = header.parentElement.querySelector('.card-body').id;
        const closeBtn = header.querySelector('.close-section');
        if (!closeBtn) {
          const controls = document.createElement('div');
          controls.innerHTML = `
            <button class="btn btn-link text-secondary close-section" onclick="closeSection(event, '${sectionId}')">
              <i class="fas fa-times"></i>
            </button>
            <i id="${sectionId}-icon" class="fas fa-chevron-down toggle-icon"></i>
          `;
          header.appendChild(controls);
        }
      });

      // ...existing DOMContentLoaded code...
    });
  </script>

  
</body>
</html>
