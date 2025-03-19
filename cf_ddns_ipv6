<?php

################ CLOUDFLARE CREDENTIALS ################
$auth_email = "";
$auth_method = "token";  // "global" or "token"
$auth_key = "";
$zone_identifier = "";

################ DNS RECORD CONFIGURATION ################
$record_name = "";
$ttl = 1;
$proxy = false;

// Script Configuration
$static_IPv6_mode = false;
$last_notable_hexes = "ffff:ffff";
$log_header_name = "DDNS Updater_v6";

// Webhooks Configuration (Optional)
$sitename = "";
$slackchannel = "";
$slackuri = "";
$discorduri = "";

// Check IPv6 Connectivity
function checkIPv6Connectivity() {
    $url = "https://ipv6.google.com"; // 使用 Google 的 IPv6 测试站点
    $ch = curl_init($url);
    
    // 设置 cURL 选项
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_NOBODY, true);
    curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    
    // 解决 SSL 证书问题的两种方法
    // 方法 1: 禁用 SSL 验证 (不太安全，但适合测试目的)
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    
    /* 
    // 方法 2: 指定证书文件路径 (更安全，但需要下载证书文件)
    // curl_setopt($ch, CURLOPT_CAINFO, "path/to/cacert.pem");
    */
    
    // 执行请求
    curl_exec($ch);
    
    // 获取信息
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error_code = curl_errno($ch);
    $error_message = curl_error($ch);
    
    // 关闭 cURL 连接
    curl_close($ch);
    
    // 显示信息
    if ($error_code) {
        echo "cURL 错误 (" . $error_code . "): " . $error_message . "\n";
        return false;
    } else {
        echo "HTTP code: " . $http_code . "\n";
        return ($http_code === 200);
    }
}

if (!checkIPv6Connectivity()) {
    echo "$log_header_name: Unable to establish a valid IPv6 connection.";
    exit(1);
}

// Get IPv6 Address

function getIPv6($static_IPv6_mode, $last_notable_hexes) {
    if ($static_IPv6_mode) {
        exec("ipconfig /all", $output);
        foreach ($output as $line) {
            // 改进正则表达式，更精确地匹配 IPv6 地址
            if (preg_match('/IPv6 Address.*: ([0-9a-f:]+)/i', $line, $matches)) {
                // 替换 PHP 8.0 的 str_ends_with 函数
                $ipv6 = $matches[1];
                if (substr($ipv6, -strlen($last_notable_hexes)) === $last_notable_hexes) {
                    return $ipv6;
                }
            }
        }
        
        // 如果没有找到匹配的 IPv6，尝试匹配任何 IPv6 地址
        foreach ($output as $line) {
            if (preg_match('/IPv6 Address.*: ([0-9a-f:]+)/i', $line, $matches)) {
                return $matches[1];
            }
        }
    } else {
        $urls = [
            "https://api64.ipify.org",
            "https://ipv6.icanhazip.com",
            "https://cloudflare.com/cdn-cgi/trace"
        ];
        
        foreach ($urls as $url) {
            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);
            
            // 禁用 SSL 验证以解决证书问题
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
            
            $response = curl_exec($ch);
            $error = curl_errno($ch);
            curl_close($ch);
            
            if (!$error && $response) {
                // 处理 Cloudflare 的特殊响应格式
                if (strpos($url, "cloudflare.com") !== false) {
                    if (preg_match('/ip=([0-9a-f:]+)/i', $response, $matches)) {
                        $ipv6 = $matches[1];
                        if (filter_var($ipv6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                            return $ipv6;
                        }
                    }
                } else {
                    // 处理其他 API 的响应
                    $ipv6 = trim($response);
                    if (filter_var($ipv6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                        return $ipv6;
                    }
                }
            }
        }
    }
    
    return false;
}

// 测试函数
$ipv6 = getIPv6(true, "966a"); // 测试本地 IPv6
if ($ipv6) {
    echo ";Local IPv6 address: " . $ipv6 . "\n";
} else {
    echo "Could not find local IPv6 address.\n";
    
    // 如果本地查找失败，尝试在线查询
    $ipv6 = getIPv6(false, "");
    if ($ipv6) {
        echo "Public IPv6 address: " . $ipv6 . "\n";
    } else {
        echo "Could not find IPv6 address，Please check if it's support IPv6\n";
    }
}

$ipv6 = getIPv6($static_IPv6_mode, $last_notable_hexes);
if (!$ipv6) {
    echo "$log_header_name: Unable to determine IPv6 address.";
    exit(1);
}


// Set Authentication Header
$auth_header = ($auth_method === "global") ? "X-Auth-Key: $auth_key" : "Authorization: Bearer $auth_key";

// Check Existing AAAA Record
$ch = curl_init("https://api.cloudflare.com/client/v4/zones/$zone_identifier/dns_records?type=AAAA&name=$record_name");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    "X-Auth-Email: $auth_email",
    $auth_header,
    "Content-Type: application/json"
]);

// 添加错误处理和SSL验证禁用（如有需要）
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);

// 执行请求并捕获原始响应
$response = curl_exec($ch);

// 检查是否有错误
if (curl_errno($ch)) {
    echo "cURL Error: " . curl_error($ch) . "\n";
}

// 获取HTTP状态码
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
echo "HTTP Status Code: " . $http_code . "\n\n";

curl_close($ch);

// 输出原始响应
echo "Raw Response:\n";
echo $response . "\n\n";

// 解析JSON
$data = json_decode($response, true);

// 检查JSON解析是否成功
if (json_last_error() !== JSON_ERROR_NONE) {
    echo "JSON Error: " . json_last_error_msg() . "\n";
}

// 正确输出数组内容
echo "Parsed Data:\n";
//print_r($data);
if ($data['result_info']['count'] == 0) {
    echo "$log_header_name: Record does not exist ($ipv6 for $record_name).";
    exit(1);
}

// Extract Existing IP
$record_identifier = $data['result'][0]['id'];
$old_ip = $data['result'][0]['content'];
if (!filter_var($old_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
    echo "$log_header_name: Unable to extract existing IPv6 address.";
    exit(1);
}

// Check if IP Needs Update
if ($ipv6 === $old_ip) {
    echo "$log_header_name: IP ($ipv6) for $record_name has not changed.";
    exit(0);
}

// Update Cloudflare DNS Record
$update_data = json_encode([
    "content" => $ipv6,
    "ttl" => $ttl,
    "proxied" => $proxy
]);

$ch = curl_init("https://api.cloudflare.com/client/v4/zones/$zone_identifier/dns_records/$record_identifier");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PATCH");
curl_setopt($ch, CURLOPT_POSTFIELDS, $update_data);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    "X-Auth-Email: $auth_email",
    $auth_header,
    "Content-Type: application/json"
]);

// 添加SSL证书验证禁用（Windows Server 2008上可能需要）
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);

// 添加调试输出
echo "Updating DNS record...\n";
echo "URL: https://api.cloudflare.com/client/v4/zones/$zone_identifier/dns_records/$record_identifier\n";
echo "Data: $update_data\n";

// 执行请求
$update_response = curl_exec($ch);

// 检查cURL错误
if (curl_errno($ch)) {
    echo "cURL error: " . curl_error($ch) . "\n";
    exit(1);
}

// 获取HTTP状态码
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
echo "HTTP状态码: $http_code\n";

curl_close($ch);

// 输出原始响应
echo "API responce: $update_response\n";

// 解析JSON响应
$update_result = json_decode($update_response, true);

// 检查JSON解析错误
if (json_last_error() !== JSON_ERROR_NONE) {
    echo "JSON Decode error: " . json_last_error_msg() . "\n";
    exit(1);
}

// 检查API响应是否成功
if (!isset($update_result['success']) || !$update_result['success']) {
    $error_message = isset($update_result['errors']) ? json_encode($update_result['errors']) : "unknow error";
    echo "update failed: $error_message\n";
    echo "$log_header_name: Unable to update DDNS（$ipv6 用于 $record_name）。response: " . json_encode($update_result);
    exit(1);
}

// 记录成功
echo "Success updated DNS record! New IPv6 address: $ipv6\n";
echo "$log_header_name: updated $record_name new ipv6 address: $ipv6";

// 发送通知（Slack和Discord）
function sendNotification($uri, $message) {
    if (empty($uri)) return;
    
    $payload = json_encode(["content" => $message]);
    $ch = curl_init($uri);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["Content-Type: application/json"]);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    
    $result = curl_exec($ch);
    
    // 检查通知是否成功发送
    if (curl_errno($ch)) {
        echo "Sending  Notification Failed: " . curl_error($ch) . "\n";
    }
    
    curl_close($ch);
}

// 检查通知URI是否已设置
if (!empty($slackuri) || !empty($discorduri)) {
    echo "Sending Notification...\n";
}

sendNotification($slackuri, "$sitename updated: $record_name new ipv6 address $ipv6");
sendNotification($discorduri, "$sitename updated: $record_name new ipv6 address $ipv6");

exit(0);

?>
