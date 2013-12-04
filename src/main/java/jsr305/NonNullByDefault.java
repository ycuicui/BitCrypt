/*******************************************************************************
 * Copyright (c) 2011 Stephan Herrmann and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     Stephan Herrmann - initial API and implementation
 *     IBM Corporation - bug fixes
 *******************************************************************************/
package jsr305;

import static java.lang.annotation.ElementType.CONSTRUCTOR;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.PACKAGE;
import static java.lang.annotation.ElementType.TYPE;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * This annotation can be applied to a package, type, method or constructor in
 * order to define that all contained entities for which a null annotation is
 * otherwise lacking should be considered as {@link NonNull @NonNull}.
 * <dl>
 * <dt>Canceling a default</dt>
 * <dd>By using a <code>@NonNullByDefault</code> annotation with the argument
 * <code>false</code>, a default from any enclosing scope can be canceled for
 * the element being annotated.
 * <dt>Nested defaults</dt>
 * <dd>If a <code>@NonNullByDefault</code> annotation is used within the scope
 * of another <code>@NonNullByDefault</code> annotation or a project-wide
 * default setting, the innermost annotation defines the default applicable at
 * any given position (depending on the parameter {@link #value()}).</dd>
 * </dl>
 * Note that for applying an annotation to a package, a file by the name
 * <code>package-info.java</code> is used.
 */
@Documented
@Retention(RetentionPolicy.CLASS)
@Target({ PACKAGE, TYPE, METHOD, CONSTRUCTOR })
public @interface NonNullByDefault {
	/**
	 * When parameterized with <code>false</code>, the annotation specifies that
	 * the current element should not apply any default to non annotated types.
	 */
	boolean value() default true;
}
