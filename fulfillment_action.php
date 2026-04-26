<?php
declare(strict_types=1);

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

$baseDir = dirname(__DIR__, 1);
$dbLoaded = false;

$dbCandidates = [
    $baseDir . '/config/db.php',
    $baseDir . '/includes/db.php',
    dirname($baseDir) . '/config/db.php',
    dirname($baseDir) . '/includes/db.php',
];

foreach ($dbCandidates as $dbFile) {
    if (is_file($dbFile)) {
        require_once $dbFile;
        $dbLoaded = true;
        break;
    }
}

if (!$dbLoaded) {
    http_response_code(500);
    exit('Database configuration not found.');
}

$pdo = null;
if (isset($pdo) && $pdo instanceof PDO) {
    // already set
} elseif (isset($db) && $db instanceof PDO) {
    $pdo = $db;
} elseif (isset($conn) && $conn instanceof PDO) {
    $pdo = $conn;
}

if (!$pdo instanceof PDO) {
    http_response_code(500);
    exit('Database connection is unavailable.');
}

$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

function seller_redirect_with_flash(string $type, string $message, string $fallbackUrl, ?string $returnUrl = null): void
{
    $_SESSION['seller_fulfillment_flash'] = [
        'type' => $type,
        'message' => $message,
    ];

    $target = $fallbackUrl;
    if (is_string($returnUrl) && $returnUrl !== '') {
        $parts = parse_url($returnUrl);
        $isLocal = isset($parts['path']) && strpos((string)$parts['path'], '/') === 0 && !isset($parts['scheme']) && !isset($parts['host']);
        if ($isLocal) {
            $target = $returnUrl;
        }
    }

    header('Location: ' . $target);
    exit;
}

function detect_actor(array $session): array
{
    $idCandidates = [
        $session['user']['id'] ?? null,
        $session['auth_user']['id'] ?? null,
        $session['member']['id'] ?? null,
        $session['seller']['id'] ?? null,
        $session['user_id'] ?? null,
        $session['member_id'] ?? null,
        $session['seller_id'] ?? null,
    ];

    $sellerId = null;
    foreach ($idCandidates as $candidate) {
        if ($candidate !== null && $candidate !== '' && ctype_digit((string)$candidate)) {
            $sellerId = (int)$candidate;
            break;
        }
    }

    $roleCandidates = [
        $session['user']['role'] ?? null,
        $session['auth_user']['role'] ?? null,
        $session['member']['role'] ?? null,
        $session['seller']['role'] ?? null,
        $session['role'] ?? null,
        $session['user_role'] ?? null,
        $session['member_role'] ?? null,
    ];

    $role = null;
    foreach ($roleCandidates as $candidate) {
        if (is_string($candidate) && $candidate !== '') {
            $role = strtolower(trim($candidate));
            break;
        }
    }

    $isAdmin = in_array($role, ['admin', 'superadmin', 'super_admin'], true);
    $isSeller = in_array($role, ['seller', 'vendor', 'merchant'], true) || isset($session['seller']) || isset($session['seller_id']);

    return [$sellerId, $isSeller, $isAdmin];
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit('Method not allowed');
}

[$actorId, $isSeller, $isAdmin] = detect_actor($_SESSION);

if (!$actorId || (!$isSeller && !$isAdmin)) {
    http_response_code(403);
    exit('Forbidden');
}

$sessionCsrf = $_SESSION['_csrf_seller_order']['fulfillment'] ?? '';
$postCsrf = isset($_POST['csrf_token']) ? (string)$_POST['csrf_token'] : '';

if (!is_string($sessionCsrf) || $sessionCsrf === '' || $postCsrf === '' || !hash_equals($sessionCsrf, $postCsrf)) {
    http_response_code(403);
    exit('Invalid CSRF token');
}

$orderItemId = isset($_POST['order_item_id']) ? (int)$_POST['order_item_id'] : 0;
$action = isset($_POST['action']) ? strtolower(trim((string)$_POST['action'])) : '';
$carrier = trim((string)($_POST['carrier'] ?? ''));
$trackingNumber = trim((string)($_POST['tracking_number'] ?? ''));
$fulfillmentNote = trim((string)($_POST['fulfillment_note'] ?? ''));
$returnUrl = isset($_POST['return_url']) ? (string)$_POST['return_url'] : null;

if ($orderItemId <= 0 || !in_array($action, ['process', 'ship', 'complete'], true)) {
    seller_redirect_with_flash('error', 'Invalid fulfillment request.', '/seller/orders.php', $returnUrl);
}

$stmt = $pdo->prepare(
    'SELECT oi.*, l.seller_id AS listing_seller_id, l.title AS listing_title
     FROM order_items oi
     JOIN listings l ON l.id = oi.listing_id
     WHERE oi.id = ?
     LIMIT 1'
);
$stmt->execute([$orderItemId]);
$orderItem = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$orderItem) {
    seller_redirect_with_flash('error', 'Order item not found.', '/seller/orders.php', $returnUrl);
}

$itemOrderId = (int)($orderItem['order_id'] ?? 0);
$fallbackUrl = '/seller/order_detail.php?id=' . $itemOrderId;

$itemSellerId = (int)($orderItem['listing_seller_id'] ?? 0);
if (!$isAdmin && $itemSellerId !== $actorId) {
    http_response_code(403);
    exit('Forbidden');
}

$currentStatus = strtolower((string)($orderItem['fulfillment_status'] ?? 'pending'));
$allowedTransitions = [
    'process' => ['from' => ['pending'], 'to' => 'processing'],
    'ship' => ['from' => ['pending', 'processing'], 'to' => 'shipped'],
    'complete' => ['from' => ['shipped'], 'to' => 'completed'],
];

if (in_array($currentStatus, ['completed', 'cancelled'], true)) {
    seller_redirect_with_flash('error', 'This item can no longer be updated.', $fallbackUrl, $returnUrl);
}

$transition = $allowedTransitions[$action];
if (!in_array($currentStatus, $transition['from'], true)) {
    seller_redirect_with_flash('error', 'Invalid fulfillment status transition.', $fallbackUrl, $returnUrl);
}

if ($action === 'ship' && $trackingNumber === '') {
    seller_redirect_with_flash('error', 'Tracking number is required to mark as shipped.', $fallbackUrl, $returnUrl);
}

$now = (new DateTimeImmutable('now'))->format('Y-m-d H:i:s');
$newStatus = $transition['to'];

$updateParts = ['fulfillment_status = :new_status', 'fulfillment_note = :fulfillment_note'];
$params = [
    ':new_status' => $newStatus,
    ':fulfillment_note' => $fulfillmentNote !== '' ? $fulfillmentNote : null,
    ':id' => $orderItemId,
];

if ($action === 'process') {
    $updateParts[] = 'processed_at = :processed_at';
    $params[':processed_at'] = $now;
}

if ($action === 'ship') {
    $updateParts[] = 'carrier = :carrier';
    $updateParts[] = 'tracking_number = :tracking_number';
    $updateParts[] = 'shipped_at = :shipped_at';
    $params[':carrier'] = $carrier !== '' ? mb_substr($carrier, 0, 80) : null;
    $params[':tracking_number'] = mb_substr($trackingNumber, 0, 120);
    $params[':shipped_at'] = $now;
}

if ($action === 'complete') {
    $updateParts[] = 'completed_at = :completed_at';
    $params[':completed_at'] = $now;
}

$logTableExists = false;
try {
    $checkLogStmt = $pdo->query("SHOW TABLES LIKE 'order_item_logs'");
    $logTableExists = (bool)$checkLogStmt->fetchColumn();
} catch (Throwable $e) {
    $logTableExists = false;
}

$pdo->beginTransaction();

try {
    $reReadStmt = $pdo->prepare(
        'SELECT oi.*, l.seller_id AS listing_seller_id, l.title AS listing_title
         FROM order_items oi
         JOIN listings l ON l.id = oi.listing_id
         WHERE oi.id = ?
         LIMIT 1'
    );
    $reReadStmt->execute([$orderItemId]);
    $freshItem = $reReadStmt->fetch(PDO::FETCH_ASSOC);

    if (!$freshItem) {
        throw new RuntimeException('Order item no longer exists.');
    }

    $freshStatus = strtolower((string)($freshItem['fulfillment_status'] ?? 'pending'));
    $freshSellerId = (int)($freshItem['listing_seller_id'] ?? 0);

    if (!$isAdmin && $freshSellerId !== $actorId) {
        throw new RuntimeException('You do not have permission to update this item.');
    }

    if (!in_array($freshStatus, $transition['from'], true)) {
        throw new RuntimeException('Status transition is no longer valid. Please refresh and try again.');
    }

    $updateSql = 'UPDATE order_items SET ' . implode(', ', $updateParts) . ' WHERE id = :id';
    $updateStmt = $pdo->prepare($updateSql);
    $updateStmt->execute($params);

    if ($logTableExists) {
        $logStmt = $pdo->prepare(
            'INSERT INTO order_item_logs
            (order_item_id, order_id, listing_id, seller_id, action, old_status, new_status, actor_type, actor_id, note, ip_address, user_agent)
            VALUES
            (:order_item_id, :order_id, :listing_id, :seller_id, :action, :old_status, :new_status, :actor_type, :actor_id, :note, :ip_address, :user_agent)'
        );
        $logStmt->execute([
            ':order_item_id' => $orderItemId,
            ':order_id' => (int)($freshItem['order_id'] ?? 0),
            ':listing_id' => (int)($freshItem['listing_id'] ?? 0),
            ':seller_id' => $freshSellerId,
            ':action' => $action,
            ':old_status' => $freshStatus,
            ':new_status' => $newStatus,
            ':actor_type' => $isAdmin ? 'admin' : 'seller',
            ':actor_id' => $actorId,
            ':note' => $fulfillmentNote !== '' ? $fulfillmentNote : null,
            ':ip_address' => isset($_SERVER['REMOTE_ADDR']) ? mb_substr((string)$_SERVER['REMOTE_ADDR'], 0, 45) : null,
            ':user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? mb_substr((string)$_SERVER['HTTP_USER_AGENT'], 0, 255) : null,
        ]);
    }

    $countsStmt = $pdo->prepare(
        'SELECT
            SUM(CASE WHEN fulfillment_status = "completed" THEN 1 ELSE 0 END) AS completed_count,
            SUM(CASE WHEN fulfillment_status = "shipped" THEN 1 ELSE 0 END) AS shipped_count,
            SUM(CASE WHEN fulfillment_status IN ("pending", "processing") THEN 1 ELSE 0 END) AS pending_processing_count,
            COUNT(*) AS total_count
         FROM order_items
         WHERE order_id = ?'
    );
    $countsStmt->execute([(int)$freshItem['order_id']]);
    $counts = $countsStmt->fetch(PDO::FETCH_ASSOC) ?: [];

    $completedCount = (int)($counts['completed_count'] ?? 0);
    $shippedCount = (int)($counts['shipped_count'] ?? 0);
    $pendingProcessingCount = (int)($counts['pending_processing_count'] ?? 0);
    $totalCount = (int)($counts['total_count'] ?? 0);

    if ($totalCount > 0) {
        if ($completedCount === $totalCount) {
            $syncCompletedStmt = $pdo->prepare(
                "UPDATE orders SET status = 'completed' WHERE id = ? AND status NOT IN ('cancelled', 'refunded')"
            );
            $syncCompletedStmt->execute([(int)$freshItem['order_id']]);
        } elseif ($shippedCount > 0 && $pendingProcessingCount === 0) {
            $syncShippedStmt = $pdo->prepare(
                "UPDATE orders SET status = 'shipped' WHERE id = ? AND status IN ('paid','confirmed','processing','packing')"
            );
            $syncShippedStmt->execute([(int)$freshItem['order_id']]);
        }
    }

    $pdo->commit();

    seller_redirect_with_flash('success', 'Fulfillment updated successfully.', $fallbackUrl, $returnUrl);
} catch (Throwable $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    seller_redirect_with_flash('error', $e->getMessage(), $fallbackUrl, $returnUrl);
}
