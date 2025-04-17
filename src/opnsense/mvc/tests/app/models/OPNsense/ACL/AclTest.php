<?php
namespace tests\OPNsense\Base;

use OPNsense\Core\AppConfig;
use OPNsense\Core\Config;
use OPNsense\Core\ACL;

class AclTest extends \PHPUnit\Framework\TestCase
{
    private static $acl = null;

    /**
     * test construct
     */
    public function testCanBeCreated()
    {
        // switch config to test set for this type
        (new AppConfig())->update('globals.config_path', __DIR__ . '/AclConfig/');
        Config::getInstance()->forceReload();
        /* init after config reload */
        AclTest::$acl = new ACL();
        $this->assertInstanceOf('\OPNsense\Core\ACL', AclTest::$acl);
    }

    /**
     * @depends testCanBeCreated
     */
    public function test_root_hasPrivilege_not()
    {
        $this->assertFalse(AclTest::$acl->hasPrivilege('root', 'user-config-readonly'));
    }

    /**
     * @depends testCanBeCreated
     */
    public function test_test1_hasPrivilege()
    {
        $this->assertTrue(AclTest::$acl->hasPrivilege('test1', 'user-config-readonly'));
    }

    /**
     * @depends testCanBeCreated
     */
    public function test_test2_hasPrivilege_via_group()
    {
        $this->assertTrue(AclTest::$acl->hasPrivilege('test2', 'user-config-readonly'));
    }

    /**
     * @depends testCanBeCreated
     */
    public function test_test3_hasPrivilege_not()
    {
        $this->assertFalse(AclTest::$acl->hasPrivilege('test3', 'user-config-readonly'));
    }

    /**
     * @depends testCanBeCreated
     */
    public function test_root_isPageAccessible_known()
    {
        $this->assertTrue(AclTest::$acl->isPageAccessible('root', '/ui/diagnostics/interface/arp/'));
    }

    /**
     * @depends testCanBeCreated
     */
    public function test_root_isPageAccessible_unknown()
    {
        $this->assertTrue(AclTest::$acl->isPageAccessible('root', '/non_existing_page'));
    }

    /**
     * @depends testCanBeCreated
     */
    public function test_test2_isPageAccessible()
    {
        $this->assertTrue(AclTest::$acl->isPageAccessible('test2', '/ui/diagnostics/interface/arp/'));
    }

    /**
     * @depends testCanBeCreated
     */
    public function test_test4_isPageAccessible_via_group()
    {
        $this->assertTrue(AclTest::$acl->isPageAccessible('test4', '/ui/diagnostics/interface/arp/'));
    }

    /**
     * @depends testCanBeCreated
     */
    public function test_test1_isPageAccessible_unknown()
    {
        $this->assertFalse(AclTest::$acl->isPageAccessible('test1', '/ui/diagnostics/interface/arp/'));
    }

    /**
     * @depends testCanBeCreated
     */
    public function test_licenseControllerDoesNotExists()
    {
        $viewPath = 'src/opnsense/mvc/app/controllers/OPNsense/Core/LicenseController.php';
        $this->assertFileDoesNotExist($viewPath);
    }
}
