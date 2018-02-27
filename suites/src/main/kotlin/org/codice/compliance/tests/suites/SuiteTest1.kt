package org.codice.compliance.tests.suites

import org.codice.compliance.tests.PostLoginTest
import org.codice.compliance.tests.RedirectLoginTest
import org.junit.runner.RunWith
import org.junit.runners.Suite

@RunWith(Suite::class)
@Suite.SuiteClasses(PostLoginTest::class,
        RedirectLoginTest::class)
class SuiteTest1