<?php
/**
 * PHP迷你密码箱 - 安全存储您的敏感信息
 * 采用AES-256-CBC加密算法保护数据安全
 */

// 配置信息
define('DATA_FILE', __DIR__ . '/.vault_data');
define('FILES_DIR', __DIR__ . '/.vault_files');
define('ENCRYPTION_ALGO', 'AES-256-CBC');

// 确保文件目录存在
if (!file_exists(FILES_DIR)) {
    mkdir(FILES_DIR, 0700, true);
}

// 错误处理函数
function handleError($message, $redirect = true) {
    $_SESSION['error'] = $message;
    if ($redirect) {
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }
}

// 初始化会话
session_start();

// 生成CSRF令牌
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// 检查是否已登录
$isLoggedIn = isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true;

// 处理登录请求
if (isset($_POST['login'])) {
    // 验证CSRF令牌
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        handleError('安全令牌验证失败，请重试');
    }
    
    $masterPassword = $_POST['master_password'];
    
    // 如果数据文件不存在，创建新的密码箱
    if (!file_exists(DATA_FILE)) {
        $salt = random_bytes(16);
        $key = hash_pbkdf2('sha256', $masterPassword, $salt, 100000, 32, true);
        $iv = random_bytes(openssl_cipher_iv_length(ENCRYPTION_ALGO));
        $data = json_encode(['entries' => [], 'notes' => [], 'files' => []]);
        $encryptedData = openssl_encrypt($data, ENCRYPTION_ALGO, $key, 0, $iv);
        
        $vaultData = base64_encode($salt) . '|' . base64_encode($iv) . '|' . base64_encode($encryptedData);
        file_put_contents(DATA_FILE, $vaultData);
        
        $_SESSION['authenticated'] = true;
        $_SESSION['master_password'] = $masterPassword;
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        // 验证现有密码箱
        $vaultData = file_get_contents(DATA_FILE);
        list($encodedSalt, $encodedIv, $encodedEncryptedData) = explode('|', $vaultData);
        
        $salt = base64_decode($encodedSalt);
        $key = hash_pbkdf2('sha256', $masterPassword, $salt, 100000, 32, true);
        $iv = base64_decode($encodedIv);
        $encryptedData = base64_decode($encodedEncryptedData);
        
        $decryptedData = openssl_decrypt($encryptedData, ENCRYPTION_ALGO, $key, 0, $iv);
        
        if ($decryptedData !== false) {
            $_SESSION['authenticated'] = true;
            $_SESSION['master_password'] = $masterPassword;
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
        } else {
            handleError('主密码错误');
        }
    }
}

// 处理登出请求
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// 已登录用户的功能处理
if ($isLoggedIn) {
    $masterPassword = $_SESSION['master_password'];
    
    // 读取并解密数据
    $vaultData = file_get_contents(DATA_FILE);
    list($encodedSalt, $encodedIv, $encodedEncryptedData) = explode('|', $vaultData);
    
    $salt = base64_decode($encodedSalt);
    $key = hash_pbkdf2('sha256', $masterPassword, $salt, 100000, 32, true);
    $iv = base64_decode($encodedIv);
    $encryptedData = base64_decode($encodedEncryptedData);
    
    $data = json_decode(openssl_decrypt($encryptedData, ENCRYPTION_ALGO, $key, 0, $iv), true);
    $entries = $data['entries'] ?? [];
    $notes = $data['notes'] ?? [];
    $files = $data['files'] ?? [];
    
    // 添加新密码条目
    if (isset($_POST['add_entry'])) {
        // 验证CSRF令牌
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            handleError('安全令牌验证失败，请重试');
        }
        
        $newEntry = [
            'id' => uniqid(),
            'title' => $_POST['title'],
            'username' => $_POST['username'],
            'password' => $_POST['password'],
            'url' => $_POST['url'],
            'notes' => $_POST['notes'],
            'created_at' => date('Y-m-d H:i:s'),
            'updated_at' => date('Y-m-d H:i:s')
        ];
        
        $entries[] = $newEntry;
        $data['entries'] = $entries;
        
        // 加密并保存数据
        $encryptedData = openssl_encrypt(json_encode($data), ENCRYPTION_ALGO, $key, 0, $iv);
        $vaultData = base64_encode($salt) . '|' . base64_encode($iv) . '|' . base64_encode($encryptedData);
        file_put_contents(DATA_FILE, $vaultData);
        
        header('Location: ' . $_SERVER['PHP_SELF'] . '?tab=entries&success=1');
        exit;
    }
    
    // 编辑密码条目
    if (isset($_POST['edit_entry'])) {
        // 验证CSRF令牌
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            handleError('安全令牌验证失败，请重试');
        }
        
        $entryId = $_POST['entry_id'];
        $index = array_search($entryId, array_column($entries, 'id'));
        
        if ($index !== false) {
            $entries[$index] = [
                'id' => $entryId,
                'title' => $_POST['title'],
                'username' => $_POST['username'],
                'password' => $_POST['password'],
                'url' => $_POST['url'],
                'notes' => $_POST['notes'],
                'created_at' => $entries[$index]['created_at'],
                'updated_at' => date('Y-m-d H:i:s')
            ];
            
            $data['entries'] = $entries;
            
            // 加密并保存数据
            $encryptedData = openssl_encrypt(json_encode($data), ENCRYPTION_ALGO, $key, 0, $iv);
            $vaultData = base64_encode($salt) . '|' . base64_encode($iv) . '|' . base64_encode($encryptedData);
            file_put_contents(DATA_FILE, $vaultData);
        }
        
        header('Location: ' . $_SERVER['PHP_SELF'] . '?tab=entries&success=1');
        exit;
    }
    
    // 添加新笔记
    if (isset($_POST['add_note'])) {
        // 验证CSRF令牌
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            handleError('安全令牌验证失败，请重试');
        }
        
        $newNote = [
            'id' => uniqid(),
            'title' => $_POST['note_title'],
            'content' => $_POST['note_content'],
            'created_at' => date('Y-m-d H:i:s'),
            'updated_at' => date('Y-m-d H:i:s')
        ];
        
        $notes[] = $newNote;
        $data['notes'] = $notes;
        
        // 加密并保存数据
        $encryptedData = openssl_encrypt(json_encode($data), ENCRYPTION_ALGO, $key, 0, $iv);
        $vaultData = base64_encode($salt) . '|' . base64_encode($iv) . '|' . base64_encode($encryptedData);
        file_put_contents(DATA_FILE, $vaultData);
        
        header('Location: ' . $_SERVER['PHP_SELF'] . '?tab=notes&success=1');
        exit;
    }
    
    // 编辑笔记
    if (isset($_POST['edit_note'])) {
        // 验证CSRF令牌
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            handleError('安全令牌验证失败，请重试');
        }
        
        $noteId = $_POST['note_id'];
        $index = array_search($noteId, array_column($notes, 'id'));
        
        if ($index !== false) {
            $notes[$index] = [
                'id' => $noteId,
                'title' => $_POST['note_title'],
                'content' => $_POST['note_content'],
                'created_at' => $notes[$index]['created_at'],
                'updated_at' => date('Y-m-d H:i:s')
            ];
            
            $data['notes'] = $notes;
            
            // 加密并保存数据
            $encryptedData = openssl_encrypt(json_encode($data), ENCRYPTION_ALGO, $key, 0, $iv);
            $vaultData = base64_encode($salt) . '|' . base64_encode($iv) . '|' . base64_encode($encryptedData);
            file_put_contents(DATA_FILE, $vaultData);
        }
        
        header('Location: ' . $_SERVER['PHP_SELF'] . '?tab=notes&success=1');
        exit;
    }
    
    // 上传文件
    if (isset($_POST['upload_file'])) {
        // 验证CSRF令牌
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            handleError('安全令牌验证失败，请重试');
        }
        
        if (isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
            $fileId = uniqid();
            $fileName = $_FILES['file']['name'];
            $fileTmpName = $_FILES['file']['tmp_name'];
            $fileSize = $_FILES['file']['size'];
            $fileType = $_FILES['file']['type'];
            
            // 检查文件大小限制（10MB）
            if ($fileSize > 10 * 1024 * 1024) {
                handleError('文件大小超过10MB限制');
            }
            
            $filePath = FILES_DIR . '/' . $fileId;
            
            // 加密文件内容
            $fileContent = file_get_contents($fileTmpName);
            $fileIv = random_bytes(openssl_cipher_iv_length(ENCRYPTION_ALGO));
            $encryptedFileContent = openssl_encrypt($fileContent, ENCRYPTION_ALGO, $key, 0, $fileIv);
            
            // 保存加密文件（包含IV）
            if (file_put_contents($filePath, base64_encode($fileIv) . '|' . $encryptedFileContent) === false) {
                handleError('无法保存文件，请检查目录权限');
            }
            
            $newFile = [
                'id' => $fileId,
                'name' => $fileName,
                'size' => $fileSize,
                'type' => $fileType,
                'created_at' => date('Y-m-d H:i:s')
            ];
            
            $files[] = $newFile;
            $data['files'] = $files;
            
            // 加密并保存数据
            $encryptedData = openssl_encrypt(json_encode($data), ENCRYPTION_ALGO, $key, 0, $iv);
            $vaultData = base64_encode($salt) . '|' . base64_encode($iv) . '|' . base64_encode($encryptedData);
            file_put_contents(DATA_FILE, $vaultData);
            
            header('Location: ' . $_SERVER['PHP_SELF'] . '?tab=files&success=1');
            exit;
        } else {
            handleError('文件上传失败');
        }
    }
    
    // 更改主密码
    if (isset($_POST['change_master_password'])) {
        // 验证CSRF令牌
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            handleError('安全令牌验证失败，请重试');
        }
        
        $currentPassword = $_POST['current_password'];
        $newPassword = $_POST['new_password'];
        $confirmPassword = $_POST['confirm_password'];
        
        // 验证当前密码
        $currentKey = hash_pbkdf2('sha256', $currentPassword, $salt, 100000, 32, true);
        $testDecrypt = openssl_decrypt($encryptedData, ENCRYPTION_ALGO, $currentKey, 0, $iv);
        
        if ($testDecrypt === false) {
            handleError('当前密码不正确');
        }
        
        if (empty($newPassword) || strlen($newPassword) < 8) {
            handleError('新密码长度至少为8个字符');
        }
        
        if ($newPassword !== $confirmPassword) {
            handleError('新密码和确认密码不匹配');
        }
        
        // 生成新的盐和IV
        $newSalt = random_bytes(16);
        $newKey = hash_pbkdf2('sha256', $newPassword, $newSalt, 100000, 32, true);
        $newIv = random_bytes(openssl_cipher_iv_length(ENCRYPTION_ALGO));
        
        // 使用新密钥重新加密数据
        $newEncryptedData = openssl_encrypt(json_encode($data), ENCRYPTION_ALGO, $newKey, 0, $newIv);
        $newVaultData = base64_encode($newSalt) . '|' . base64_encode($newIv) . '|' . base64_encode($newEncryptedData);
        
        if (file_put_contents(DATA_FILE, $newVaultData) === false) {
            handleError('无法保存新密码，请检查文件权限');
        }
        
        // 更新会话
        $_SESSION['master_password'] = $newPassword;
        
        header('Location: ' . $_SERVER['PHP_SELF'] . '?tab=settings&success=1');
        exit;
    }
    
    // 生成随机密码
    function generatePassword($length = 16, $includeSpecialChars = true) {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        if ($includeSpecialChars) {
            $chars .= '!@#$%^&*()_+~`|}{[]:;?><,./-=';
        }
        
        $password = '';
        $charsLength = strlen($chars);
        
        for ($i = 0; $i < $length; $i++) {
            $password .= $chars[random_int(0, $charsLength - 1)];
        }
        
        return $password;
    }
    
    if (isset($_GET['generate_password'])) {
        header('Content-Type: application/json');
        echo json_encode(['password' => generatePassword()]);
        exit;
    }
    
    // 导出所有数据
    if (isset($_GET['export'])) {
        header('Content-Type: application/json');
        header('Content-Disposition: attachment; filename="vault_export_' . date('YmdHis') . '.json"');
        echo json_encode($data, JSON_PRETTY_PRINT);
        exit;
    }
}
?>

<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHP迷你密码箱</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/npm/font-awesome@4.7.0/css/font-awesome.min.css" rel="stylesheet">
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        primary: '#165DFF',
                        secondary: '#69b1ff',
                        dark: '#1D2939',
                        light: '#F9FAFB'
                    },
                    fontFamily: {
                        inter: ['Inter', 'system-ui', 'sans-serif'],
                    },
                }
            }
        }
    </script>
    <style type="text/tailwindcss">
        @layer utilities {
            .content-auto {
                content-visibility: auto;
            }
            .card-shadow {
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
            }
            .btn-primary {
                @apply bg-primary hover:bg-primary/90 text-white font-medium py-2 px-4 rounded-lg transition-all duration-300 transform hover:scale-[1.02] focus:outline-none focus:ring-2 focus:ring-primary/50;
            }
            .btn-secondary {
                @apply bg-white border border-gray-300 hover:bg-gray-50 text-dark font-medium py-2 px-4 rounded-lg transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-gray-200;
            }
            .input-field {
                @apply w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all duration-300;
            }
            .fade-in {
                animation: fadeIn 0.5s ease-in-out;
            }
            @keyframes fadeIn {
                from { opacity: 0; transform: translateY(10px); }
                to { opacity: 1; transform: translateY(0); }
            }
        }
    </style>
</head>
<body class="font-inter bg-gray-50 min-h-screen">
    <div class="container mx-auto px-4 py-8 max-w-6xl">
        <?php if (!$isLoggedIn): ?>
            <!-- 登录界面 -->
            <div class="max-w-md mx-auto mt-16 bg-white rounded-2xl card-shadow p-8 fade-in">
                <div class="text-center mb-8">
                    <i class="fa fa-lock text-5xl text-primary mb-4"></i>
                    <h1 class="text-[clamp(1.5rem,3vw,2rem)] font-bold text-dark">PHP迷你密码箱</h1>
                    <p class="text-gray-500 mt-2">安全存储您的敏感信息</p>
                </div>
                
                <?php if (isset($_SESSION['error'])): ?>
                    <div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg mb-4">
                        <i class="fa fa-exclamation-circle mr-2"></i>
                        <?php echo $_SESSION['error']; unset($_SESSION['error']); ?>
                    </div>
                <?php endif; ?>
                
                <form method="post" class="space-y-4">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    
                    <div>
                        <label for="master_password" class="block text-sm font-medium text-gray-700 mb-1">主密码</label>
                        <div class="relative">
                            <input type="password" id="master_password" name="master_password" class="input-field" required>
                            <button type="button" id="toggle_password" class="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600">
                                <i class="fa fa-eye-slash"></i>
                            </button>
                        </div>
                        <p class="text-xs text-gray-500 mt-1">请记住您的主密码，遗忘后将无法恢复数据</p>
                    </div>
                    
                    <button type="submit" name="login" class="btn-primary w-full">
                        <i class="fa fa-unlock-alt mr-2"></i>解锁密码箱
                    </button>
                </form>
                
                <div class="mt-6 text-center text-sm text-gray-500">
                    <p>使用强加密算法保护您的数据安全</p>
                    <p class="mt-1">版本 1.0.0</p>
                </div>
            </div>
        <?php else: ?>
            <!-- 主界面 -->
            <div class="flex flex-col h-screen">
                <!-- 顶部导航 -->
                <header class="bg-white rounded-xl card-shadow p-4 mb-6 flex justify-between items-center">
                    <div class="flex items-center space-x-3">
                        <i class="fa fa-lock text-2xl text-primary"></i>
                        <h1 class="text-xl font-bold text-dark">PHP迷你密码箱</h1>
                    </div>
                    
                    <div class="flex items-center space-x-4">
                        <button id="export_btn" class="btn-secondary text-sm">
                            <i class="fa fa-download mr-1"></i>导出数据
                        </button>
                        <button id="change_password_btn" class="btn-secondary text-sm">
                            <i class="fa fa-key mr-1"></i>更改主密码
                        </button>
                        <a href="?logout" class="btn-secondary text-sm">
                            <i class="fa fa-sign-out mr-1"></i>退出
                        </a>
                    </div>
                </header>
                
                <!-- 成功提示 -->
                <?php if (isset($_GET['success'])): ?>
                    <div class="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded-lg mb-4 fade-in">
                        <i class="fa fa-check-circle mr-2"></i>
                        操作成功完成
                    </div>
                <?php endif; ?>
                
                <!-- 主内容区 -->
                <main class="flex-1 flex flex-col md:flex-row gap-6">
                    <!-- 侧边栏 -->
                    <aside class="w-full md:w-64 shrink-0">
                        <div class="bg-white rounded-xl card-shadow p-4 h-full">
                            <nav class="space-y-2">
                                <a href="?tab=entries" class="flex items-center p-3 rounded-lg text-dark hover:bg-gray-50 transition-all duration-200 <?php echo (isset($_GET['tab']) && $_GET['tab'] === 'entries') || !isset($_GET['tab']) ? 'bg-primary/10 text-primary font-medium' : ''; ?>">
                                    <i class="fa fa-keyboard-o w-5 text-center mr-3"></i>
                                    <span>密码管理</span>
                                </a>
                                
                                <a href="?tab=notes" class="flex items-center p-3 rounded-lg text-dark hover:bg-gray-50 transition-all duration-200 <?php echo (isset($_GET['tab']) && $_GET['tab'] === 'notes') ? 'bg-primary/10 text-primary font-medium' : ''; ?>">
                                    <i class="fa fa-sticky-note-o w-5 text-center mr-3"></i>
                                    <span>私密笔记</span>
                                </a>
                                
                                <a href="?tab=files" class="flex items-center p-3 rounded-lg text-dark hover:bg-gray-50 transition-all duration-200 <?php echo (isset($_GET['tab']) && $_GET['tab'] === 'files') ? 'bg-primary/10 text-primary font-medium' : ''; ?>">
                                    <i class="fa fa-file-o w-5 text-center mr-3"></i>
                                    <span>文件存储</span>
                                </a>
                                
                                <a href="?tab=settings" class="flex items-center p-3 rounded-lg text-dark hover:bg-gray-50 transition-all duration-200 <?php echo (isset($_GET['tab']) && $_GET['tab'] === 'settings') ? 'bg-primary/10 text-primary font-medium' : ''; ?>">
                                    <i class="fa fa-cog w-5 text-center mr-3"></i>
                                    <span>设置</span>
                                </a>
                            </nav>
                            
                            <div class="mt-8 p-4 bg-gray-50 rounded-lg">
                                <h3 class="font-medium text-gray-700 mb-2">统计信息</h3>
                                <div class="space-y-2 text-sm">
                                    <div class="flex justify-between">
                                        <span class="text-gray-500">密码条目:</span>
                                        <span class="font-medium"><?php echo count($entries); ?></span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-gray-500">笔记数量:</span>
                                        <span class="font-medium"><?php echo count($notes); ?></span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-gray-500">文件数量:</span>
                                        <span class="font-medium"><?php echo count($files); ?></span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </aside>
                    
                    <!-- 内容区域 -->
                    <section class="flex-1 overflow-y-auto">
                        <!-- 密码管理 -->
                        <?php if ((isset($_GET['tab']) && $_GET['tab'] === 'entries') || !isset($_GET['tab'])): ?>
                            <div class="bg-white rounded-xl card-shadow p-6 fade-in">
                                <div class="flex justify-between items-center mb-6">
                                    <h2 class="text-xl font-bold text-dark">密码管理</h2>
                                    <button id="add_entry_btn" class="btn-primary">
                                        <i class="fa fa-plus mr-2"></i>添加新密码
                                    </button>
                                </div>
                                
                                <!-- 搜索框 -->
                                <div class="mb-6 relative">
                                    <input type="text" id="search_entries" placeholder="搜索密码..." class="input-field pl-10">
                                    <i class="fa fa-search absolute left-3 top-1/2 -translate-y-1/2 text-gray-400"></i>
                                </div>
                                
                                <!-- 密码列表 -->
                                <div class="overflow-x-auto">
                                    <table class="min-w-full divide-y divide-gray-200">
                                        <thead>
                                            <tr>
                                                <th class="px-4 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">标题</th>
                                                <th class="px-4 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">用户名</th>
                                                <th class="px-4 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">密码</th>
                                                <th class="px-4 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">操作</th>
                                            </tr>
                                        </thead>
                                        <tbody class="bg-white divide-y divide-gray-200">
                                            <?php if (empty($entries)): ?>
                                                <tr>
                                                    <td colspan="4" class="px-4 py-8 text-center text-gray-500">
                                                        <i class="fa fa-folder-open-o text-3xl mb-2 block"></i>
                                                        暂无密码条目
                                                    </td>
                                                </tr>
                                            <?php else: ?>
                                                <?php foreach ($entries as $entry): ?>
                                                    <tr class="hover:bg-gray-50 transition-colors duration-150">
                                                        <td class="px-4 py-4 whitespace-nowrap">
                                                            <div class="font-medium text-dark">
                                                                <?php echo htmlspecialchars($entry['title']); ?>
                                                            </div>
                                                            <div class="text-sm text-gray-500">
                                                                <?php echo htmlspecialchars($entry['url']); ?>
                                                            </div>
                                                        </td>
                                                        <td class="px-4 py-4 whitespace-nowrap">
                                                            <div class="text-sm text-gray-900">
                                                                <?php echo htmlspecialchars($entry['username']); ?>
                                                            </div>
                                                        </td>
                                                        <td class="px-4 py-4 whitespace-nowrap">
                                                            <div class="flex items-center">
                                                                <input type="password" value="<?php echo htmlspecialchars($entry['password']); ?>" readonly class="input-field bg-transparent border-none p-0 w-48 focus:ring-0 text-sm">
                                                                <button type="button" class="ml-2 text-gray-400 hover:text-primary" onclick="togglePasswordVisibility(this)">
                                                                    <i class="fa fa-eye-slash"></i>
                                                                </button>
                                                            </div>
                                                        </td>
                                                        <td class="px-4 py-4 whitespace-nowrap text-sm font-medium">
                                                            <button class="text-primary hover:text-primary/80 mr-3 edit-entry" data-id="<?php echo $entry['id']; ?>">
                                                                <i class="fa fa-pencil mr-1"></i>编辑
                                                            </button>
                                                            <a href="?delete_entry=<?php echo $entry['id']; ?>" class="text-red-600 hover:text-red-900 delete-entry">
                                                                <i class="fa fa-trash mr-1"></i>删除
                                                            </a>
                                                        </td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            <?php endif; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        <?php endif; ?>
                        
                        <!-- 私密笔记 -->
                        <?php if (isset($_GET['tab']) && $_GET['tab'] === 'notes'): ?>
                            <div class="bg-white rounded-xl card-shadow p-6 fade-in">
                                <div class="flex justify-between items-center mb-6">
                                    <h2 class="text-xl font-bold text-dark">私密笔记</h2>
                                    <button id="add_note_btn" class="btn-primary">
                                        <i class="fa fa-plus mr-2"></i>添加新笔记
                                    </button>
                                </div>
                                
                                <!-- 搜索框 -->
                                <div class="mb-6 relative">
                                    <input type="text" id="search_notes" placeholder="搜索笔记..." class="input-field pl-10">
                                    <i class="fa fa-search absolute left-3 top-1/2 -translate-y-1/2 text-gray-400"></i>
                                </div>
                                
                                <!-- 笔记列表 -->
                                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                    <?php if (empty($notes)): ?>
                                        <div class="col-span-full bg-gray-50 rounded-lg p-8 text-center text-gray-500">
                                            <i class="fa fa-file-text-o text-3xl mb-2 block"></i>
                                            暂无笔记
                                        </div>
                                    <?php else: ?>
                                        <?php foreach ($notes as $note): ?>
                                            <div class="bg-gray-50 rounded-lg p-4 hover:shadow-md transition-all duration-200 border border-gray-100">
                                                <div class="flex justify-between items-start mb-2">
                                                    <h3 class="font-medium text-dark truncate"><?php echo htmlspecialchars($note['title']); ?></h3>
                                                    <div class="flex space-x-1">
                                                        <button class="text-primary hover:text-primary/80 p-1 edit-note" data-id="<?php echo $note['id']; ?>">
                                                            <i class="fa fa-pencil"></i>
                                                        </button>
                                                        <a href="?delete_note=<?php echo $note['id']; ?>" class="text-red-600 hover:text-red-900 p-1 delete-note">
                                                            <i class="fa fa-trash"></i>
                                                        </a>
                                                    </div>
                                                </div>
                                                <p class="text-sm text-gray-600 mb-3 line-clamp-3">
                                                    <?php echo htmlspecialchars($note['content']); ?>
                                                </p>
                                                <div class="text-xs text-gray-400">
                                                    <?php echo date('Y-m-d H:i', strtotime($note['updated_at'])); ?>
                                                </div>
                                            </div>
                                        <?php endforeach; ?>
                                    <?php endif; ?>
                                </div>
                            </div>
                        <?php endif; ?>
                        
                        <!-- 文件存储 -->
                        <?php if (isset($_GET['tab']) && $_GET['tab'] === 'files'): ?>
                            <div class="bg-white rounded-xl card-shadow p-6 fade-in">
                                <div class="flex justify-between items-center mb-6">
                                    <h2 class="text-xl font-bold text-dark">文件存储</h2>
                                    <label for="file_upload" class="btn-primary cursor-pointer">
                                        <i class="fa fa-upload mr-2"></i>上传文件
                                    </label>
                                    <input type="file" id="file_upload" class="hidden" />
                                </div>
                                
                                <!-- 搜索框 -->
                                <div class="mb-6 relative">
                                    <input type="text" id="search_files" placeholder="搜索文件..." class="input-field pl-10">
                                    <i class="fa fa-search absolute left-3 top-1/2 -translate-y-1/2 text-gray-400"></i>
                                </div>
                                
                                <!-- 文件列表 -->
                                <div class="overflow-x-auto">
                                    <table class="min-w-full divide-y divide-gray-200">
                                        <thead>
                                            <tr>
                                                <th class="px-4 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">文件名</th>
                                                <th class="px-4 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">文件类型</th>
                                                <th class="px-4 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">大小</th>
                                                <th class="px-4 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">上传时间</th>
                                                <th class="px-4 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">操作</th>
                                            </tr>
                                        </thead>
                                        <tbody class="bg-white divide-y divide-gray-200">
                                            <?php if (empty($files)): ?>
                                                <tr>
                                                    <td colspan="5" class="px-4 py-8 text-center text-gray-500">
                                                        <i class="fa fa-cloud-upload text-3xl mb-2 block"></i>
                                                        暂无文件
                                                    </td>
                                                </tr>
                                            <?php else: ?>
                                                <?php foreach ($files as $file): ?>
                                                    <tr class="hover:bg-gray-50 transition-colors duration-150">
                                                        <td class="px-4 py-4 whitespace-nowrap">
                                                            <div class="flex items-center">
                                                                <i class="fa fa-file-o text-gray-400 mr-3"></i>
                                                                <div>
                                                                    <div class="font-medium text-dark">
                                                                        <?php echo htmlspecialchars($file['name']); ?>
                                                                    </div>
                                                                </div>
                                                            </div>
                                                        </td>
                                                        <td class="px-4 py-4 whitespace-nowrap">
                                                            <div class="text-sm text-gray-900">
                                                                <?php echo htmlspecialchars($file['type']); ?>
                                                            </div>
                                                        </td>
                                                        <td class="px-4 py-4 whitespace-nowrap">
                                                            <div class="text-sm text-gray-900">
                                                                <?php echo round($file['size'] / 1024, 2) . ' KB'; ?>
                                                            </div>
                                                        </td>
                                                        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-500">
                                                            <?php echo date('Y-m-d H:i', strtotime($file['created_at'])); ?>
                                                        </td>
                                                        <td class="px-4 py-4 whitespace-nowrap text-sm font-medium">
                                                            <a href="?download_file=<?php echo $file['id']; ?>" class="text-primary hover:text-primary/80 mr-3">
                                                                <i class="fa fa-download mr-1"></i>下载
                                                            </a>
                                                            <a href="?delete_file=<?php echo $file['id']; ?>" class="text-red-600 hover:text-red-900 delete-file">
                                                                <i class="fa fa-trash mr-1"></i>删除
                                                            </a>
                                                        </td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            <?php endif; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        <?php endif; ?>
                        
                        <!-- 设置 -->
                        <?php if (isset($_GET['tab']) && $_GET['tab'] === 'settings'): ?>
                            <div class="bg-white rounded-xl card-shadow p-6 fade-in">
                                <h2 class="text-xl font-bold text-dark mb-6">设置</h2>
                                
                                <div class="space-y-6">
                                    <div class="bg-gray-50 p-4 rounded-lg">
                                        <h3 class="font-medium text-dark mb-4">密码箱信息</h3>
                                        <div class="space-y-3">
                                            <div class="flex justify-between">
                                                <span class="text-gray-600">创建时间:</span>
                                                <span class="font-medium">
                                                    <?php 
                                                    if (file_exists(DATA_FILE)) {
                                                        echo date('Y-m-d H:i:s', filectime(DATA_FILE));
                                                    } else {
                                                        echo '未知';
                                                    }
                                                    ?>
                                                </span>
                                            </div>
                                            <div class="flex justify-between">
                                                <span class="text-gray-600">上次更新:</span>
                                                <span class="font-medium">
                                                    <?php 
                                                    if (file_exists(DATA_FILE)) {
                                                        echo date('Y-m-d H:i:s', filemtime(DATA_FILE));
                                                    } else {
                                                        echo '未知';
                                                    }
                                                    ?>
                                                </span>
                                            </div>
                                            <div class="flex justify-between">
                                                <span class="text-gray-600">数据大小:</span>
                                                <span class="font-medium">
                                                    <?php 
                                                    if (file_exists(DATA_FILE)) {
                                                        echo round(filesize(DATA_FILE) / 1024, 2) . ' KB';
                                                    } else {
                                                        echo '0 KB';
                                                    }
                                                    ?>
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <div class="bg-gray-50 p-4 rounded-lg">
                                        <h3 class="font-medium text-dark mb-4">安全信息</h3>
                                        <div class="space-y-3">
                                            <div class="flex justify-between">
                                                <span class="text-gray-600">加密算法:</span>
                                                <span class="font-medium"><?php echo ENCRYPTION_ALGO; ?></span>
                                            </div>
                                            <div class="flex justify-between">
                                                <span class="text-gray-600">哈希迭代次数:</span>
                                                <span class="font-medium">100,000</span>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <div class="bg-gray-50 p-4 rounded-lg">
                                        <h3 class="font-medium text-dark mb-4">备份与恢复</h3>
                                        <div class="space-y-3">
                                            <button id="export_full_btn" class="btn-secondary">
                                                <i class="fa fa-download mr-2"></i>导出完整备份
                                            </button>
                                            <div class="flex items-center space-x-3">
                                                <input type="file" id="import_file" class="hidden" accept=".json" />
                                                <button id="import_btn" class="btn-secondary">
                                                    <i class="fa fa-upload mr-2"></i>导入备份文件
                                                </button>
                                                <span class="text-sm text-gray-500">
                                                    警告: 导入将覆盖现有数据
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        <?php endif; ?>
                    </section>
                </main>
            </div>
        <?php endif; ?>
    </div>
    
    <!-- 添加/编辑密码模态框 -->
