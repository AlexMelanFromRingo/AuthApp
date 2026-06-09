package ua.authapp.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

// Статична схема — фолбек для пристроїв без Material You (API < 31)
private val LightColors = lightColorScheme(
    primary = Color(0xFF1B5E9E),
    secondary = Color(0xFF4A6572),
    tertiary = Color(0xFF6B4F9E),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF9FCAFF),
    secondary = Color(0xFFB1C5D0),
    tertiary = Color(0xFFCFBCFF),
)

/** Тема Material 3: динамічні кольори Material You з API 31, інакше статична схема. */
@Composable
fun AuthAppTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val colorScheme = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColors
        else -> LightColors
    }
    MaterialTheme(colorScheme = colorScheme, content = content)
}
