package ua.authapp.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController

/** Маршрути додатка. */
object Routes {
    const val TOKENS = "tokens"
    const val ADD = "add"
    const val OCRA = "ocra"
    const val MIGRATION = "migration"
    const val EXPORT = "export"
    const val IMPORT = "import"
}

/**
 * Кореневий граф навігації за біометричним бар'єром: повернення з фону
 * (ON_STOP) знову блокує додаток (FR-002).
 */
@Composable
fun AppNav() {
    var unlocked by remember { mutableStateOf(false) }

    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) unlocked = false
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    if (!unlocked) {
        UnlockScreen(onUnlocked = { unlocked = true })
        return
    }

    val navController = rememberNavController()
    NavHost(navController = navController, startDestination = Routes.TOKENS) {
        composable(Routes.TOKENS) {
            TokenListScreen(
                onAddToken = { navController.navigate(Routes.ADD) },
                onOpenOcra = { navController.navigate(Routes.OCRA) },
                onOpenMigration = { navController.navigate(Routes.MIGRATION) },
            )
        }
        composable(Routes.ADD) {
            AddTokenScreen(onDone = { navController.popBackStack() })
        }
        composable(Routes.OCRA) {
            OcraScreen(onBack = { navController.popBackStack() })
        }
        composable(Routes.MIGRATION) {
            MigrationScreen(
                onExport = { navController.navigate(Routes.EXPORT) },
                onImport = { navController.navigate(Routes.IMPORT) },
                onBack = { navController.popBackStack() },
            )
        }
        composable(Routes.EXPORT) {
            ExportScreen(onBack = { navController.popBackStack() })
        }
        composable(Routes.IMPORT) {
            ImportScreen(onBack = { navController.popBackStack() })
        }
    }
}
